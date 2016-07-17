/* 1617, Sat 10 May 14 (NZST)

   natkit.c: RubyLibtrace, python version!

   python-libtrace: a Python module to make it easy to use libtrace
   Copyright (C) 2015 by Nevil Brownlee, U Auckland | WAND

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <Python.h>
#include "structmember.h"

#include "libtrace.h"
#include "plt.h"
#include "pv.h"

extern PyObject *ipp_IPprefix;  /* ipp.IPprefix() object */
extern PyObject *plt_Data;      /* plt.Data() object */

void quack(int which) {};  /* breakpoint for debugger */

static PyObject *ba_get_short(DataObject *self, PyObject *args) {
   PyObject *arg = NULL;  int x;
   if (!PyArg_ParseTuple(args, "Oi", (PyObject *)&arg, &x)) return NULL;
   if (!PyByteArray_CheckExact(arg)) return NULL;
   uint8_t *ba = (uint8_t *)PyByteArray_AsString((PyObject *)arg);
   int ba_sz = (int)PyByteArray_Size((PyObject *)arg);
   if (x+2 > ba_sz) {
      PyObject *result = Py_None;  Py_INCREF(result);  return result;
      }
   return PV_PyInt_FromLong(ntohs(*(uint16_t *)&ba[x]));
   }
static PyObject *ba_get_long(DataObject *self, PyObject *args) {
   PyObject *arg = NULL;  int x;
   if (!PyArg_ParseTuple(args, "Oi", (PyObject *)&arg, &x)) return NULL;
   if (!PyByteArray_CheckExact(arg)) return NULL;
   uint8_t *ba = (uint8_t *)PyByteArray_AsString((PyObject *)arg);
   int ba_sz = (int)PyByteArray_Size((PyObject *)arg);
   if (x+4 > ba_sz) {
      PyObject *result = Py_None;  Py_INCREF(result); return result;
      }
   return PV_PyInt_FromLong(ntohl(*(uint32_t *)&ba[x]));
   }

static PyObject *seq_add(DataObject *self, PyObject *args) {
   unsigned long a, b;
   if (!PyArg_ParseTuple(args, "kk:u32_add", &a, &b))
      return NULL;
   uint32_t ua = (uint32_t)a, ub = (uint32_t)b;
   PyObject *result = PyLong_FromUnsignedLong((uint32_t)(ua+ub));
   if (result == NULL) return NULL;
   return result;
   }
static PyObject *seq_sub(DataObject *self, PyObject *args) {
   unsigned long a, b;
   if (!PyArg_ParseTuple(args, "kk:u32_sub", &a, &b))
      return NULL;
   int32_t ua = (int32_t)a, ub = (int32_t)b;
   PyObject *result = PyLong_FromUnsignedLong((uint32_t)(ua-ub));
   if (result == NULL) return NULL;
   return result;
   }

/* Algorithm for sequence-number comparison from
      http://en.academic.ru/dic.nsf/enwiki/1197489
   (an improvement over that given in RFC 1982) */
static PyObject *seq_gt(DataObject *self, PyObject *args) {
   unsigned long s1, s2;
   if (!PyArg_ParseTuple(args, "kk:seq_gt", &s1, &s2))
      return NULL;
   int32_t i1 = (int32_t)s1, i2 = (int32_t)s2;
   int32_t d = i1-i2;
   PyObject *result = d > 0 ? Py_True : Py_False;
   Py_INCREF(result);  return result;
   }
static PyObject *seq_ge(DataObject *self, PyObject *args) {
   unsigned long s1, s2;
   if (!PyArg_ParseTuple(args, "kk:seq_ge", &s1, &s2))
      return NULL;
   int32_t i1 = (int32_t)s1, i2 = (int32_t)s2;
   int32_t d = i1-i2;
   PyObject *result = d >= 0 ? Py_True : Py_False;
   Py_INCREF(result);  return result;
   }
static PyObject *seq_lt(DataObject *self, PyObject *args) {
   unsigned long s1, s2;
   if (!PyArg_ParseTuple(args, "kk:seq_lt", &s1, &s2))
      return NULL;
   int32_t i1 = (int32_t)s1, i2 = (int32_t)s2;
   int32_t d = i1-i2;
   PyObject *result = d < 0 ? Py_True : Py_False;
   Py_INCREF(result);  return result;
   }

static PyMethodDef module_methods[] = {
   {"ba_get_short", (PyCFunction)ba_get_short, METH_VARARGS,
    "Get short from byte array"},
   {"ba_get_long", (PyCFunction)ba_get_long, METH_VARARGS,
   "Get long from byte array"},
   {"seq_add", (PyCFunction)seq_add, METH_VARARGS,
    "Unsigned 32-bit add"},
   {"seq_sub", (PyCFunction)seq_sub, METH_VARARGS,
    "Unsigned 32-bit subtract"},
   {"seq_gt", (PyCFunction)seq_gt, METH_VARARGS,
    "TCP seq nbr >"},
   {"seq_ge", (PyCFunction)seq_ge, METH_VARARGS,
    "TCP seq nbr >="},
   {"seq_lt", (PyCFunction)seq_lt, METH_VARARGS,
    "TCP seq nbr <"},
   {NULL}  /* Sentinel */
   };


#define FT_FIRST_PKT  0  /* Default.  First pkt src->dst */
#define FT_HOME_FLOW  1  /* src->dst means inward to Home network */

typedef struct {  /* Python stuff starts here */
   PyObject_HEAD
   uint8_t flow_type, inward, src_home, dst_home;
   struct {
      uint8_t version, proto;
      uint16_t sport, dport;  /* Bytes in network order */
      union {
	 struct {
            uint8_t saddr[4], daddr[4];
	    } v4;
	 struct {
            uint8_t saddr[16], daddr[16];
	    } v6;
         } addrs;
      } fkey;
   } IPflowObject;

static IPflowObject *get_IPflow(IPflowObject *ipf, PyObject *arg) {
   if (!PyObject_IsInstance(arg, plt_Data)) {
      PyErr_SetString(PyExc_ValueError,
         "IPflow: arg not DataType");  return NULL;
   }
   DataObject *dp = (DataObject *)arg;
   if (dp->kind != RLT_KIND_PKT) {
      PyErr_SetString(PyExc_ValueError,
         "Object didn't come from a plt Packet");  return NULL;
      }
   uint16_t ethertype = dp->ethertype; void *l3p = dp->l3p;
   uint32_t remaining = dp->l3_rem;
   if (dp->l3p == NULL || ethertype == 0) {
      remaining = dp->l2_rem;
      l3p = trace_get_payload_from_layer2(
         dp->l2p, dp->linktype, &ethertype, &remaining);
      }
   if (l3p) {
      if (remaining < 4) {
         PyErr_SetString(PyExc_ValueError,
            "pkt capture_len to short to get ports");  return NULL;
         }
      uint8_t version = 0, proto = 0,
         *psrc_addr = NULL, *pdst_addr = NULL;
      uint16_t src_port = 0, dst_port = 0;
      void *l4p;
      libtrace_tcp_t *ltcp;  libtrace_udp_t *ludp;
      if (ethertype == 0x0800) {
         version = 4;
         l4p = trace_get_payload_from_ip(
            (libtrace_ip_t *)l3p, &proto, &remaining);
	 if (l4p && proto == 6) {
	    ltcp = (libtrace_tcp_t *)l4p;
	    src_port = ltcp->source;  dst_port = ltcp->dest;
	    }
	 else if (l4p && proto == 17) {
	    ludp = (libtrace_udp_t *)l4p;
	    src_port = ludp->source;  dst_port = ludp->dest;
	    }
	 psrc_addr =  (uint8_t *)&((libtrace_ip_t *)l3p)->ip_src;
	 pdst_addr =  (uint8_t *)&((libtrace_ip_t *)l3p)->ip_dst;
         }
      else if (ethertype == 0x86dd) {
         version = 6;
         l4p = trace_get_payload_from_ip6(
            (libtrace_ip6_t *)l3p, &proto, &remaining);
	 if (l4p && proto == 6) {
	    ltcp = (libtrace_tcp_t *)l4p;
	    src_port = ltcp->source;  dst_port = ltcp->dest;
	    }
	 else if (l4p && proto == 17) {
	    ludp = (libtrace_udp_t *)l4p;
	    src_port = ludp->source;  dst_port = ludp->dest;
	    }
	 psrc_addr =  (uint8_t *)&((libtrace_ip6_t *)l3p)->ip_src;
	 pdst_addr =  (uint8_t *)&((libtrace_ip6_t *)l3p)->ip_dst;
         }
      else {
         PyErr_SetString(PyExc_ValueError, "Not an IP packet");
         return NULL;
         }
      ipf->fkey.version = version;  ipf->fkey.proto = proto;
      ipf->fkey.sport = src_port;  ipf->fkey.dport = dst_port;
      if (version == 4) {
       	 memcpy(ipf->fkey.addrs.v4.saddr, psrc_addr, 4);
	 memcpy(ipf->fkey.addrs.v4.daddr, pdst_addr, 4);
         }
      else {
       	 memcpy(ipf->fkey.addrs.v6.saddr, psrc_addr, 16);
	 memcpy(ipf->fkey.addrs.v6.daddr, pdst_addr, 16);
         }
      return ipf;
      }
   PyErr_SetString(PyExc_ValueError, "Couldn't get Layer3 data");
   return NULL;
   }

static void IPflow_dealloc(PyObject *self) {
   self->ob_type->tp_free((PyObject *)self);
   }

static PyObject *IPflow_new(PyTypeObject *type, PyObject *args) {
   IPflowObject *self = (IPflowObject *)type->tp_alloc(type, 0);
   return (PyObject *)self;
   }

static int IPflow_init(IPflowObject *self, PyObject *args) {
   PyObject *dp = NULL;
   if (!PyArg_ParseTuple(args, "O:Data", &dp)) {
      PyErr_SetString(PyExc_ValueError, "Expected an object");
      return -1;
      }
   IPflowObject *ipf = get_IPflow(self, dp);
   if (ipf == NULL) return -1;
   self->flow_type = FT_FIRST_PKT;
   self->src_home = self->dst_home = 0;
   return 0;
   }

static PyObject *IPflow_fwd_key(IPflowObject *self) {
   PyObject *result;  char key[2+4+32];
   key[0] = self->fkey.version;
   key[1] = self->fkey.proto;
   memcpy(&key[2], &self->fkey.sport, 2);
   memcpy(&key[4], &self->fkey.dport, 2);
   if (self->fkey.version == 4) {
      memcpy(&key[6], self->fkey.addrs.v4.saddr, 4);
      memcpy(&key[10], self->fkey.addrs.v4.daddr, 4);
      result = PV_PyString_FromStringAndSize_bytes(key, 14);
      }
   else {
      memcpy(&key[6], self->fkey.addrs.v6.saddr, 16);
      memcpy(&key[22], self->fkey.addrs.v6.daddr, 16);
      result = PV_PyString_FromStringAndSize_bytes(key, 38);
      }
   if (result == NULL) return NULL;
   return result;
   }
set_read_only(fwd_key);

static PyObject *IPflow_rev_key(IPflowObject *self) {
   PyObject *result;  char key[2+4+32];
   key[0] = self->fkey.version;
   key[1] = self->fkey.proto;
   memcpy(&key[2], &self->fkey.dport, 2);
   memcpy(&key[4], &self->fkey.sport, 2);
   if (self->fkey.version == 4) {
      memcpy(&key[6], self->fkey.addrs.v4.daddr, 4);
      memcpy(&key[10], self->fkey.addrs.v4.saddr, 4);
      result = PV_PyString_FromStringAndSize_bytes(key, 14);
      }
   else {
      memcpy(&key[6], self->fkey.addrs.v6.daddr, 16);
      memcpy(&key[22], self->fkey.addrs.v6.saddr, 16);
      result = PV_PyString_FromStringAndSize_bytes(key, 38);
      }
   if (result == NULL) return NULL;
   return result;
   }
set_read_only(rev_key);

static PyObject *IPflow_version(IPflowObject *self) {
   PyObject *result = PV_PyInt_FromLong((long)self->fkey.version);
   if (result == NULL) return NULL;
   return result;
   }
set_read_only(version);

static PyObject *IPflow_proto(IPflowObject *self) {
   PyObject *result = PV_PyInt_FromLong((long)self->fkey.proto);
   if (result == NULL) return NULL;
   return result;
   }
set_read_only(proto);

static PyObject *IPflow_sport(IPflowObject *self) {
   PyObject *result = PV_PyInt_FromLong((long)ntohs(self->fkey.sport));
   if (result == NULL) return NULL;
   return result;
   }
set_read_only(sport);

static PyObject *IPflow_dport(IPflowObject *self) {
   PyObject *result = PV_PyInt_FromLong((long)ntohs(self->fkey.dport));
   if (result == NULL) return NULL;
   return result;
   }
set_read_only(dport);

static PyObject *IPflow_saddr(IPflowObject *self) {
  uint8_t *sap;  PyObject *ba, *pArgs;
   if (self->fkey.version == 4) {
      sap = self->fkey.addrs.v4.saddr;
      ba = PyByteArray_FromStringAndSize((char *)sap, 4);
      }
   else {
      sap = self->fkey.addrs.v6.saddr;
      ba = PyByteArray_FromStringAndSize((char *)sap, 16);
      }
   pArgs = Py_BuildValue("iO", self->fkey.version, ba);
   PyObject *r = PyObject_CallObject(ipp_IPprefix, pArgs);
   Py_DECREF(pArgs);  Py_DECREF(ba);
   return r;
   }
set_read_only(saddr);

static PyObject *IPflow_daddr(IPflowObject *self) {
  uint8_t *dap;  PyObject *ba, *pArgs;
   if (self->fkey.version == 4) {
      dap = self->fkey.addrs.v4.daddr;
      ba = PyByteArray_FromStringAndSize((char *)dap, 4);
      }
   else {
      dap = self->fkey.addrs.v6.daddr;
      ba = PyByteArray_FromStringAndSize((char *)dap, 16);
      }
   pArgs = Py_BuildValue("iO", self->fkey.version, ba);
   PyObject *r = PyObject_CallObject(ipp_IPprefix, pArgs);
   Py_DECREF(pArgs);  Py_DECREF(ba);
   return r;
   }
set_read_only(daddr);

static PyObject *IPflow_home_key(IPflowObject *self) {
   PyObject *result;  char key[2+4+32];
   if (self->flow_type == FT_HOME_FLOW) {
      key[0] = self->fkey.version;
      key[1] = self->fkey.proto;
      if (self->dst_home) {
         memcpy(&key[2], &self->fkey.sport, 2);
         memcpy(&key[4], &self->fkey.dport, 2);
         }
      else {
         memcpy(&key[2], &self->fkey.dport, 2);
         memcpy(&key[4], &self->fkey.sport, 2);
         }
      if (self->fkey.version == 4) {
         if (self->dst_home) {
            memcpy(&key[6], self->fkey.addrs.v4.saddr, 4);
            memcpy(&key[10], self->fkey.addrs.v4.daddr, 4);
            }
         else {
            memcpy(&key[6], self->fkey.addrs.v4.daddr, 4);
            memcpy(&key[10], self->fkey.addrs.v4.saddr, 4);
            }
         result = PV_PyString_FromStringAndSize_bytes(key, 14);
         }
      else {
         if (self->dst_home) {
            memcpy(&key[6], self->fkey.addrs.v6.saddr, 16);
            memcpy(&key[22], self->fkey.addrs.v6.daddr, 16);
            }
         else {
            memcpy(&key[6], self->fkey.addrs.v6.daddr, 16);
            memcpy(&key[22], self->fkey.addrs.v6.saddr, 16);
            }
         result = PV_PyString_FromStringAndSize_bytes(key, 38);
         }
      if (result != NULL) return result;
      return NULL;
      }
   result = Py_None;  Py_INCREF(result);  return result;
   }
set_read_only(home_key);

static PyObject *IPflow_src_in_home(IPflowObject *self) {
   PyObject *result = Py_None;
   if (self->flow_type == FT_HOME_FLOW)
      result = self->src_home ? Py_True : Py_False;
   Py_INCREF(result);  return result;
   }
set_read_only(src_in_home);

static PyObject *IPflow_dst_in_home(IPflowObject *self) {
   PyObject *result = Py_None;
   if (self->flow_type == FT_HOME_FLOW)
      result = self->dst_home ? Py_True : Py_False;
   Py_INCREF(result);  return result;
   return NULL;
   }
set_read_only(dst_in_home);

static PyObject *IPflow_is_inward(IPflowObject *self) {
   PyObject *result = Py_None;
   if (self->flow_type == FT_HOME_FLOW) {
      result = (self->src_home && !self->dst_home) ||
	 (!self->src_home && self->dst_home) ? Py_True : Py_False;
      }
   Py_INCREF(result);  return result;
   return NULL;
   }
set_read_only(is_inward);

static PyGetSetDef Packet_getseters[] = {
   {"fwd_key",
      (getter)IPflow_fwd_key, (setter)set_fwd_key,
      "IPflow forward key", NULL},
   {"rev_key",
      (getter)IPflow_rev_key, (setter)set_rev_key,
      "IPflow reverse key", NULL},
   {"version",
      (getter)IPflow_version, (setter)set_version,
      "IPflow version", NULL},
   {"proto",
      (getter)IPflow_proto, (setter)set_proto,
      "IPflow proto", NULL},
   {"src_port",
      (getter)IPflow_sport, (setter)set_sport,
      "IPflow src_port", NULL},
   {"dst_port",
      (getter)IPflow_dport, (setter)set_dport,
      "IPflow dst_port", NULL},
   {"src_prefix",
      (getter)IPflow_saddr, (setter)set_saddr,
      "IPflow src_prefix", NULL},
   {"dst_prefix",
      (getter)IPflow_daddr, (setter)set_daddr,
      "IPflow dst_prefix", NULL},
   {"home_key",
      (getter)IPflow_home_key, (setter)set_home_key,
      "IPflow home key", NULL},
   {"src_in_home",
      (getter)IPflow_src_in_home, (setter)set_src_in_home,
      "src_prefix in Home", NULL},
   {"dst_in_home",
      (getter)IPflow_dst_in_home, (setter)set_dst_in_home,
      "dst_prefix in_home", NULL},
   {"is_inward",
      (getter)IPflow_is_inward, (setter)set_is_inward,
      "IPflow is_inward", NULL},
   {NULL},  /* Sentinel */
   };

PyTypeObject IPflowType = {
   PV_PyObject_HEAD_INIT
   "IPflow",                  /*tp_name*/
   sizeof(IPflowObject),      /*tp_basicsize*/
   0,                         /*tp_itemsize*/
   (destructor)IPflow_dealloc,  /*tp_dealloc*/
   0,                         /*tp_print*/
   0,                         /*tp_getattr*/
   0,                         /*tp_setattr*/
   0,                         /*tp_compare*/
   0,                         /*tp_repr*/
   0,                         /*tp_as_number*/
   0,                         /*tp_as_sequence*/
   0,                         /*tp_as_mapping*/
   0,                         /*tp_hash */
   0,                         /*tp_call*/
   0,    /*tp_str*/
   //   (reprfunc)plt_str,    /*tp_str*/
   0,                         /*tp_getattro*/
   0,                         /*tp_setattro (setattr works, this doesn't) */  
   0,                         /*tp_as_buffer*/
   Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
   "Python-libtrace IPflow",  /* tp_doc */
   0,		              /* tp_traverse */
   0,		              /* tp_clear */
   0,                         /* tp_richcompare */
   0,		              /* tp_weaklistoffset */
   0,		              /* tp_iter */
   0,		              /* tp_iternext */
   0,                         /* tp_methods */
   0,                         /* tp_members */
   Packet_getseters,          /* tp_getset */
   0,                         /* tp_base */
   0,                         /* tp_dict */
   0,                         /* tp_descr_get */ 
   0,                         /* tp_descr_set */
   0,                         /* tp_dictoffset */
   (initproc)IPflow_init,    /* tp_init */
   0,                        /* tp_alloc */
   (newfunc)IPflow_new,      /* tp_new */
   };


typedef struct {
   int nw;  /* 32-bit words to test */
   uint32_t addr[4];
   uint32_t mask[4];
   } Prefix;
typedef struct {
   PyObject_HEAD
   int n_prefixes;
   Prefix *plist;
   } FlowHome;

static void FlowHome_dealloc(FlowHome *self) {
   if (self->n_prefixes != 0)  free(self->plist);
   PV_free_self;
   }

static PyObject *FlowHome_new(PyTypeObject *type, PyObject *args) {
   if (!PyTuple_Check(args)) {
      PyErr_SetString(PyExc_ValueError, "Expected a Tuple");
      return NULL;
      }
   FlowHome *self = 
      (FlowHome *)type->tp_alloc(type, 0);

   Py_ssize_t n_objs = PyTuple_Size(args);
   self->n_prefixes = (int)n_objs;
   self->plist = malloc(n_objs*sizeof(Prefix));
   if (self->plist == NULL) {
      Py_DECREF(self);
      PyErr_SetString(PyExc_ValueError,
        "Couldn't malloc Prefix array");  return NULL;
      }
   int j;  PyObject *pref;
   uint8_t addr[16], mask[16],
      bmask[8] = { 0, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe };
   Prefix *pp = self->plist;
   for (j = 0;  j != n_objs;  j += 1) {
      pref = PyTuple_GetItem(args, j);
      if (!PyObject_IsInstance(pref, ipp_IPprefix)) {
         Py_DECREF(self);
         PyErr_SetString(PyExc_ValueError, "Expected tuple of IPprefixes");
         return NULL;
         } 
      PyObject *pver = PyObject_GetAttrString(pref, "version");
      int ver = (int)PyLong_AsLong(pver);
      Py_DECREF(pver);
      PyObject *paddr = PyObject_GetAttrString(pref, "addr");
      char *caddr = PyByteArray_AsString(paddr);
      Py_DECREF(paddr);
      PyObject *plen = PyObject_GetAttrString(pref, "length");
      int len = (int)PyLong_AsLong(plen);
      Py_DECREF(plen);
      memset(addr, 0, 16);  memset(mask, 0, 16);
      memcpy(addr, caddr, ver == 4 ? 4 : 16);
      int whole = len/8;  memset(mask, 0xff, whole);
      mask[whole] = bmask[len % 8];
#if 0
      printf("version = %d, length = %d\n", ver, len);
      int k;  printf("addr %02x", addr[0]);
      for (k=1; k!=16; k+=1) printf(" %02x", addr[k]);
      printf("\nmask %02x", mask[0]);
      for (k=1; k!=16; k+=1) printf(" %02x", mask[k]); printf("\n");
#endif
      int w, nw = 0;  for (w = 0; w != 4; w += 1) {

         uint32_t *tmp = (uint32_t *)&addr[w*4];
         pp[j].addr[w] = *tmp;  /* Network byte order */
         tmp = (uint32_t *)&mask[w*4];
         pp[j].mask[w] = *tmp;
         if (pp[j].mask[w] != 0) nw += 1;
         }
      pp[j].nw = nw;
      }

   return (PyObject *)self;
   }

static int FlowHome_init(FlowHome *self, PyObject *args) {
#if 0
   int n;  for (n = 0; n != self->n_prefixes; n += 1) {
      Prefix *pp = self->plist;
      printf("%d: words to test = %d\n", n, pp[n].nw);
      int k;  printf("addr ");
      for (k=0; k!=4; k+=1) printf(" %08x", pp[n].addr[k]);
      printf("\nmask ");
      for (k=0; k!=4; k+=1) printf(" %08x", pp[n].mask[k]); printf("\n");
      }
#endif
   return 0;
   }

static PyObject *get_rr_owner(FlowHome *self, void *closure) {
   PyObject *rr_owner =  PV_PyString_FromString("dummy");
#if 0
   ldns_rdf *owner = ldns_rr_owner(self->rr);
   char *owner_s = ldns_rdf2str(owner);
   if (rr_owner == NULL) {
      PyErr_SetString(PyExc_ValueError,
         "Failed to create owner string");  return NULL;
      }
   free(owner_s);
#endif
   return rr_owner;
   }
set_read_only(rr_owner);

static PyGetSetDef FlowHome_getseters[] = {
   {"owner",
      (getter)get_rr_owner, (setter)set_rr_owner,
      "RR owner", NULL},
   {NULL},  /* Sentinel */
   };

int is_home(FlowHome *fh, uint8_t *addr) {
   uint32_t *ap = (uint32_t *)addr;
   int j, k;  Prefix *pp;
   for (j = 0;  j != fh->n_prefixes; j += 1) {
      pp = &fh->plist[j];
      for (k = 0; k != pp->nw; k += 1) {
 	 if ((ap[k] & pp->mask[k]) != pp->addr[k]) break;
         }
      if (k == pp->nw) return 1;  /* Found */
      }
   return 0;  /* Not found */
   }

static PyObject *hf_key(FlowHome *self, PyObject *args) {
   PyObject *dp = NULL;
   if (!PyArg_ParseTuple(args, "O:Data", &dp)) {
      PyErr_SetString(PyExc_ValueError, "Expected an object");
      return NULL;
      }
   IPflowObject *flow =
      (IPflowObject *)IPflowType.tp_alloc(&IPflowType, 0);
   if (flow == NULL) return NULL;
   IPflowObject *ipf = get_IPflow(flow, dp);
   if (ipf == NULL) return NULL;
   ipf->flow_type = FT_HOME_FLOW;
   if (ipf->fkey.version == 4) {
      ipf->src_home = is_home(self, ipf->fkey.addrs.v4.saddr);
      ipf->dst_home = is_home(self, ipf->fkey.addrs.v4.daddr);
      }
   else {
      ipf->src_home = is_home(self, ipf->fkey.addrs.v6.saddr);
      ipf->dst_home = is_home(self, ipf->fkey.addrs.v6.daddr);
      }
   return (PyObject *)ipf;
   }

static PyMethodDef FlowHome_methods[] = {
   {"flow", (PyCFunction)hf_key, METH_VARARGS,
    "ldns_pkt is OK" },
   {NULL}  /* Sentinel */
   };

PyTypeObject FlowHomeType = {
   PV_PyObject_HEAD_INIT
   "natkit.FlowHome",            /*tp_name*/
   sizeof(FlowHome),            /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)FlowHome_dealloc, /* *tp_dealloc*/
   0,                           /*tp_print*/
   0,                           /*tp_getattr*/
   0,                           /*tp_setattr*/
   0,                           /*tp_compare*/
   0,                           /*tp_repr*/
   0,                           /*tp_as_number*/
   0,                           /*tp_as_sequence*/
   0,                           /*tp_as_mapping*/
   0,                           /*tp_hash */
   0,                           /*tp_call*/
   0,                           /*tp_str*/
   0,                           /*tp_getattro*/
   0,                           /*tp_setattro (setattr works, this doesn't) */  
   0,                           /*tp_as_buffer*/
   Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
   "FlowHome objects",          /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   FlowHome_methods,              /* tp_methods */
   0,                           /* tp_members */
   FlowHome_getseters,          /* tp_getset */
   0,                           /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)FlowHome_init,     /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)FlowHome_new,       /* tp_new */
   };



#ifndef PyMODINIT_FUNC  /* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif

PyObject *ipp_IPprefix;  /* ipp.IPprefix() object */
PyObject *plt_Data;      /* plt.Data() object */

#if PYTHON3
static PyModuleDef natkit_module = {
    PyModuleDef_HEAD_INIT, "natkit", "python-libtrace natkit module",
            -1, module_methods, NULL, NULL, NULL, NULL
   };
#endif

#if PYTHON3
PyMODINIT_FUNC PyInit_natkit(void)  {
#define RETURN return m
#else
PyMODINIT_FUNC initnatkit(void)  {
#define RETURN return
#endif

PyObject *m=NULL;

#if PYTHON3
   m = PyModule_Create(&natkit_module);
#else
   m = Py_InitModule3("natkit", module_methods,
      "python-libtrace natkit module");
#endif
   if (m == NULL) RETURN;

   if (PyType_Ready(&IPflowType) < 0) RETURN;
   Py_TYPE(&IPflowType) = &PyType_Type;

   if (PyType_Ready(&FlowHomeType) < 0) RETURN;
   Py_TYPE(&FlowHomeType) = &PyType_Type;

   Py_INCREF(&IPflowType);
   PyModule_AddObject(m, "IPflow", (PyObject *)&IPflowType);

   Py_INCREF(&FlowHomeType);
   PyModule_AddObject(m, "FlowHome",
      (PyObject *)&FlowHomeType);

   PyObject *mainModule = PyImport_AddModule("__main__");

   PyObject *ipp_module = PyImport_ImportModule("ipp");
   PyModule_AddObject(mainModule, "ipp", ipp_module);
   PyObject *ipp_dict = PyModule_GetDict(ipp_module);
   ipp_IPprefix = PyDict_GetItemString(ipp_dict, "IPprefix");

   PyObject *plt_module = PyImport_ImportModule("plt");
   PyModule_AddObject(mainModule, "plt", plt_module);
   PyObject *plt_dict = PyModule_GetDict(plt_module);
   plt_Data = PyDict_GetItemString(plt_dict, "Data");
   RETURN;
   }
