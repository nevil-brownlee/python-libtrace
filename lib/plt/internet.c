/* 1452, Fri 14 Mar 14 (PDT)
   2141, Sun 27 Oct 13 (NZDT)

   internet.c: RubyLibtrace, python version!

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

static void internet_dealloc(PyObject *self) {
   self->ob_type->tp_free((PyObject *)self);
   }

static PyObject *internet_new(PyTypeObject *type) {
   PyObject *self = (PyObject *)type->tp_alloc(type, 0);
   return self;
   }

static int internet_init(PyObject *self) {
   return 0;
   }

static libtrace_ip_t *get_internet(DataObject *op, int x4, int x6) {
   if (!op->l3p) return NULL;
   int version = ((uint8_t *)op->l3p)[0] >> 4;
   libtrace_ip_t *lip = op->l3p;
   int l3p_len = (int)((uint8_t *)op->dp - (uint8_t *)op->l3p) + op->rem;
   if (version == 4 && l3p_len < x4) return NULL;
   else if (version == 6 && l3p_len < x6) return NULL;
   return lip;
   }

static PyObject *get_version(DataObject *self, void *closure) {
   unsigned char *p = self->l3p;  /* Was self->dp  15 Apr 15 */
   return PV_PyInt_FromLong((long)(p[0]>>4));
   }
set_read_only(version);

static PyObject *get_proto(DataObject *self, void *closure) {
   libtrace_ip_t *lip = get_internet(self, 10, 11);
   if (!lip) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for proto");  return NULL;
      }
   int version = ((uint8_t *)self->l3p)[0] >> 4;
   if (version == 4) return PV_PyInt_FromLong((long)lip->ip_p);
   else {
      uint32_t remaining = self->l3_rem;  uint8_t proto;
      void *trans = trace_get_payload_from_ip6(
         (libtrace_ip6_t *)lip, &proto, &remaining);
      if (!trans) {
         PyObject *result = Py_None;  Py_INCREF(result);  return result;
         }
      return PV_PyInt_FromLong((long)proto);
      }
   }
set_read_only(proto);

static PyObject *get_traffic_class(DataObject *self, void *closure) {
   libtrace_ip_t *lip = get_internet(self, 2, 2);
   if (!lip) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for traffic_class");  return NULL;
      }
   int version = ((uint8_t *)self->l3p)[0] >> 4;
   if (version == 4) return PV_PyInt_FromLong((long)lip->ip_tos);
   else {
      uint32_t flow = ntohl(((libtrace_ip6_t *)lip)->flow);
      return PV_PyInt_FromLong((long)((flow & 0x0FF00000) >> 20));
      }
   }
static int set_traffic_class(DataObject *self,
      PyObject *value, void *closure) {
   libtrace_ip_t *lip = get_internet(self, 2, 2);
   if (!lip) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for traffic_class");  return -1;
      }
   if (!PV_PyInt_Check(value)) {
      PyErr_SetString(PyExc_TypeError,
         "traffic class expects an integer");  return -1;
      }
   long tc = PV_PyInt_AsLong(value);
   if (tc < 0 || tc > 255) {
      PyErr_SetString(PyExc_ValueError,
         "traffic_class must be in range 0..255");  return -1;
      }
   int version = ((uint8_t *)self->l3p)[0] >> 4;
   if (version == 4) lip->ip_tos = tc;
   else {
      uint32_t flow = ntohl(((libtrace_ip6_t *)lip)->flow);
      ((libtrace_ip6_t *)lip)->flow = htonl((flow & 0xF00FFFFF) | (tc << 20));
      }
   return 0;
   }

static PyObject *get_hop_limit(DataObject *self, void *closure) {
   libtrace_ip_t *lip = get_internet(self, 9, 8);
   if (!lip) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for hop_limit");  return NULL;
      }
   int version = ((uint8_t *)self->l3p)[0] >> 4;
   if (version == 4) return PV_PyInt_FromLong((long)lip->ip_ttl);
   else return PV_PyInt_FromLong((long)((libtrace_ip6_t *)lip)->hlim);
   }
static int set_hop_limit(DataObject *self,
      PyObject *value, void *closure) {
   libtrace_ip_t *lip = get_internet(self, 9, 8);
   if (!lip) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for hop_limit");  return -1;
      }
   if (!PV_PyInt_Check(value)) {
      PyErr_SetString(PyExc_TypeError,
         "hop_limit expects an integer");  return -1;
      }
   long hl = PV_PyInt_AsLong(value);
   if (hl < 1 || hl > 255) {
      PyErr_SetString(PyExc_ValueError,
         "hop_limit must be in range 1..255");  return -1;
      }
   int version = ((uint8_t *)self->l3p)[0] >> 4;
   if (version == 4) lip->ip_ttl = hl;
   else ((libtrace_ip6_t *)lip)->hlim = hl;
   return 0;
   }

static PyObject *get_hdr_len(DataObject *self, void *closure) {
   libtrace_ip_t *lip = get_internet(self, 1, 1); 
   if (!lip) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for src_hdr_len");
      return NULL;
      }
   int version = ((uint8_t *)self->l3p)[0] >> 4;
   if (version == 4) return PV_PyInt_FromLong((long)lip->ip_hl);
   else { /* No IPv6 equivalent */
      PyObject *result = Py_None;  Py_INCREF(result);  return result;
      }
   }
set_read_only(hdr_len);

static PyObject *get_pkt_len(DataObject *self, void *closure) {
   libtrace_ip_t *lip = get_internet(self, 4, 4);
   if (!lip) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for pkt_len");  return NULL;
      }
   int version = ((uint8_t *)self->l3p)[0] >> 4;
   if (version == 4) return PV_PyInt_FromLong((long)(ntohs(lip->ip_len)));
   else { /* No IPv6 equivalent */
      PyObject *result = Py_None;  Py_INCREF(result);  return result;
      }
   }
set_read_only(pkt_len);

static PyObject *get_src_prefix(DataObject *self, void *closure) {
   libtrace_ip_t *lip = get_internet(self, 16, 24);
   if (!lip) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for src_prefix");  return NULL;
      }
   uint8_t *sap;  PyObject *pArgs;
   int version = ((uint8_t *)self->l3p)[0] >> 4;
   PyObject *ba;
   if (version == 4) {
      sap = (uint8_t *)&lip->ip_src;
      ba = PyByteArray_FromStringAndSize((char *)sap, 4);
      }
   else {
      sap = (uint8_t *)&((libtrace_ip6_t *)lip)->ip_src;
      ba = PyByteArray_FromStringAndSize((char *)sap, 16);
      }
   pArgs = Py_BuildValue("iO", version, ba);
   PyObject *r = PyObject_CallObject(ipp_new, pArgs);
   Py_DECREF(pArgs);  Py_DECREF(ba);
   return r;
   }

static int set_src_prefix(DataObject *self,
      PyObject *value, void *closure) {
   libtrace_ip_t *lip = get_internet(self, 16, 24);
   if (!lip) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for src_prefix");  return -1;
      }
   PyObject *ver_obj = PyObject_GetAttrString(value, "version"); 
   int version = (int)PV_PyInt_AsLong(ver_obj);
   PyObject *addr_obj = PyObject_GetAttrString(value, "addr");  /* Byte Array */
   const char *ap  = PyByteArray_AsString(addr_obj);
   if (version == 4)
      lip->ip_src.s_addr = (in_addr_t)*(uint32_t *)ap;
   else memcpy(((libtrace_ip6_t *)lip)->ip_src.s6_addr, ap, 16);
   return 0;
   }

static PyObject *get_dst_prefix(DataObject *self) {
   libtrace_ip_t *lip = get_internet(self, 20, 40);
   if (!lip) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for dst_prefix");  return NULL;
      }
   uint8_t *dap;  PyObject *pArgs;
   int version = ((uint8_t *)self->l3p)[0] >> 4;
   PyObject *ba;
   if (version == 4) {
      dap = (uint8_t *)&lip->ip_dst;
      ba = PyByteArray_FromStringAndSize((char *)dap, 4);
      }
   else {
      dap = (uint8_t *)&((libtrace_ip6_t *)lip)->ip_dst;
      ba = PyByteArray_FromStringAndSize((char *)dap, 16);
      }
   pArgs = Py_BuildValue("iO", version, ba);
   PyObject *r = PyObject_CallObject(ipp_new, pArgs);
   Py_DECREF(pArgs);  Py_DECREF(ba);
   return r;
   }

static int set_dst_prefix(DataObject *self,
      PyObject *value, void *closure) {
   libtrace_ip_t *lip = get_internet(self, 20, 40);
   if (!lip) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for dst_prefix");  return -1;
      }
   PyObject *ver_obj = PyObject_GetAttrString(value, "version"); 
   int version = (int)PV_PyInt_AsLong(ver_obj);
   PyObject *addr_obj = PyObject_GetAttrString(value, "addr");  /* Byte Array */
   const char *ap = PyByteArray_AsString(addr_obj);
   if (version == 4)
      lip->ip_dst.s_addr = (in_addr_t)*(uint32_t *)ap;
   else  memcpy(((libtrace_ip6_t *)lip)->ip_src.s6_addr, ap, 16);
   return 0;
   }

static PyObject *test_l3_checksum(DataObject *self) {
   if (self->kind != RLT_KIND_PKT) {
      PyErr_SetString(PyExc_ValueError,
         "Object didn't come from a plt Packet");  return NULL;
      }
   if (self->type < RLT_TYPE_L3) {
      PyErr_SetString(PyExc_ValueError,
         "Expected a Layer 3 object");  return NULL;
      }
   PyObject *result = Py_None;
   if (self->ethertype != 0x86DD) {  /* IPv6 doesn't have a header checksum */
      libtrace_ip_t *lip = (libtrace_ip_t *)self->l3p;
      if (self->l3_rem >= 1) {
	 int hlen = lip->ip_hl*4;
         if (self->l3_rem >= hlen) {
 	    uint16_t save_cks = lip->ip_sum;
            lip->ip_sum = 0;  /* Set IP checksum */
            lip->ip_sum = ~checksum(lip, lip->ip_hl*4);
	    result = lip->ip_sum == save_cks ? Py_True : Py_False;
	    }
         }
      }
   Py_INCREF(result);  return result;
   }

static PyObject *set_l3_checksum(DataObject *self) {
   if (self->kind != RLT_KIND_PKT) {
      PyErr_SetString(PyExc_ValueError,
         "Object didn't come from a plt Packet");  return NULL;
      }
   if (self->type < RLT_TYPE_L3) {
      PyErr_SetString(PyExc_ValueError,
         "Expected a Layer 3 object");  return NULL;
      }
   PyObject *result = Py_None;
   if (self->ethertype != 0x86DD) {  /* IPv6 doesn't have a header checksum */
      libtrace_ip_t *lip = (libtrace_ip_t *)self->l3p;
      if (self->l3_rem >= 1) {
	 int hlen = lip->ip_hl*4;
         if (self->l3_rem >= hlen) {
            lip->ip_sum = 0;  /* Set IP checksum */
            lip->ip_sum = ~checksum(lip, lip->ip_hl*4);
	    result = Py_True;
	    }
         }
      }
   Py_INCREF(result);  return result;
   }

static PyObject *test_trans_checksum(DataObject *self) {
   if (self->kind != RLT_KIND_PKT) {
      PyErr_SetString(PyExc_ValueError,
         "Object didn't come from a plt Packet");  return NULL;
      }
   if (self->type < RLT_TYPE_L3) {
      PyErr_SetString(PyExc_ValueError,
         "Expected a Layer 3 object");  return NULL;
      }
   PyObject *result = Py_None;
   int r = transport_checksum(self, 0);  /* Don't reset it */
   if (r >= 0) result = r ? Py_True : Py_False;
   Py_INCREF(result);  return result;
   }

static PyObject *set_trans_checksum(DataObject *self) {
   if (self->kind != RLT_KIND_PKT) {
      PyErr_SetString(PyExc_ValueError,
         "Object didn't come from a plt Packet");  return NULL;
      }
   if (self->type < RLT_TYPE_L3) {
      PyErr_SetString(PyExc_ValueError,
         "Expected a Layer 3 object");  return NULL;
      }
   PyObject *result = Py_None;
   int r = transport_checksum(self, 1);  /* Reset it */
   if (r >= 0) result = r ? Py_True : Py_False;
   Py_INCREF(result);  return result;
   }

static PyGetSetDef Internet_getseters[] = {
   {"version",
      (getter)get_version, (setter)set_version,
      "IP version", NULL},
   {"proto",
      (getter)get_proto, (setter)set_proto,
      "Network protocol", NULL},
   {"traffic_class",
      (getter)get_traffic_class, (setter)set_traffic_class,
      "TOS (IPv4), Traffic Class (IPv6)", NULL},
   {"ttl",
      (getter)get_hop_limit, (setter)set_hop_limit,
      "TTL (IPv4), Max number of hops (IPv6)", NULL},
   {"hop_limit",
      (getter)get_hop_limit, (setter)set_hop_limit,
      "TTL (IPv4), Max number of hops (IPv6)", NULL},
   {"hdr_len",
      (getter)get_hdr_len, (setter)set_hdr_len,
      "Total packet length in 4-byte units (IPv4), None (IPv6)", NULL},
   {"pkt_len",
      (getter)get_pkt_len, (setter)set_pkt_len,
      "Header length in 4-byte units (IPv4), None (IPv6)", NULL},
   {"src_prefix",
      (getter)get_src_prefix, (setter)set_src_prefix,
      "dst_prefix_name", NULL},
   {"dst_prefix",
      (getter)get_dst_prefix, (setter)set_dst_prefix,
      "dst_prefix_name", NULL},
   {NULL},  /* Sentinel */
   };

static PyMethodDef internet_methods[] = {
   {"test_l3_cksm", (PyCFunction)test_l3_checksum, METH_NOARGS,
      "Test whether layer 3 checksum is correct" },
   {"set_l3_cksm", (PyCFunction)set_l3_checksum, METH_NOARGS,
      "Reset layer 3 checksum to it's correct value" },
   {"test_trans_cksm", (PyCFunction)test_trans_checksum, METH_NOARGS,
      "Test whether transport checksum is correct" },
   {"set_trans_cksm", (PyCFunction)set_trans_checksum, METH_NOARGS,
      "Set transport checksum to it's correct value" },
   {NULL}  /* Sentinel */
   };

PyTypeObject InternetType = {
   PV_PyObject_HEAD_INIT
   "InternetObject",            /*tp_name*/
   sizeof(DataObject),          /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)internet_dealloc,  /*tp_dealloc*/
   0,                           /*tp_print*/
   0,                           /*tp_getattr*/
   0,                           /*tp_setattr*/
   // (setattrfunc)pltInternet_setattr, /*tp_setattr*/
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
   "Python-libtrace Internet",  /* tp_doc */
   0,	  	                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   internet_methods,            /* tp_methods */
   0,                           /* tp_members */
   Internet_getseters,          /* tp_getset */
   &DataType,                   /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */ 
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)internet_init,    /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)internet_new,      /* tp_new */
   };


void initinternet(void) {
   if (PyType_Ready(&InternetType) < 0) return;

   Py_TYPE(&InternetType) = &PyType_Type;

   Py_INCREF(&InternetType);
   PyModule_AddObject(plt_module, "Internet", (PyObject *)&InternetType);
   }
