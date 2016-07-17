/* 1452, Fri 14 Mar 14 (PDT)
   1421, Fri  2 Aug 13 (CEST)

   pltmodule.c: RubyLibtrace, python version!

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

char plt_err_msg[120];

static void pltData_dealloc(DataObject *self) {
   Py_XDECREF(self->mom);
   PV_free_self;
   }

static PyObject *pltData_new(PyTypeObject *type, PyObject *args) {
   DataObject *self;
   /* Users may not make new Data objects from Python */
   printf("Data_new() called ---\n");  fflush(stdout);
   self = (DataObject *)type->tp_alloc(type, 0);
   return (PyObject *)self;
   }

static int pltData_init(DataObject *self, PyObject *args) {
   return 0;
   }

DataObject *plt_new_object(  /* Make a new plt Data object */
      PyTypeObject *py_type,
      int type, int kind, void *data, PyObject *mom,
      void* l2p, int l2_rem, int linktype, int ethertype, int vlan_tag,
      void *l3p, int l3_rem, int proto,
      void *dp, int rem) {
   DataObject *d = (DataObject *)py_type->tp_alloc(py_type, 0);
   d->type = type;  d->kind = kind;  d->data = data;
   d->mom = mom;  Py_INCREF(mom);
   d->l2p = l2p;  d->l2_rem = l2_rem;
   d->linktype = linktype;  d->ethertype = ethertype;  d->vlan_tag = vlan_tag;
   d->l3p = l3p;  d->l3_rem = l3_rem;  d->proto = proto;
   d->dp = dp;  d->rem = rem;
   return d;
   }

char const *plt_type_string(int t) {
   if (t == RLT_TYPE_PKT) return "Packet";
   else if (t == RLT_TYPE_DATA) return "Data";
   else if (t == RLT_TYPE_L2) return "Layer2";
   else if (t == RLT_TYPE_L3) return "Layer3";
   else if (t == RLT_TYPE_Internet) return "Internet";
   else if (t == RLT_TYPE_IP) return "IP";
   else if (t == RLT_TYPE_IP6) return "IP6";
   else if (t == RLT_TYPE_L4) return "Transport";
   else if (t == RLT_TYPE_TCP) return "TCP";
   else if (t == RLT_TYPE_UDP) return "UDP";
   else if (t == RLT_TYPE_ICMP) return "ICMP";
   else if (t == RLT_TYPE_ICMP6) return "ICMP6";
   else if (t == RLT_TYPE_L5) return "payload";
   return "unknown";
   }

char const *plt_kind_string(int k) {
   if (k == RLT_KIND_PKT) return "packet";
   else if (k == RLT_KIND_STR) return "string";
   else if (k == RLT_KIND_CPY) return "copy";
   return "unknown";
   }

void pltData_dump(DataObject *self, const char *msg) {
   printf("%s:  %s, %s, data=%p, mom=%p\n",
      msg, plt_type_string(self->type), plt_kind_string(self->kind),
	  self->data, self->mom);
   printf("    l2p=%p, %d, %d, %04x, %04x\n",
      self->l2p, self->l2_rem, self->linktype,
      self->ethertype, self->vlan_tag);
   printf("    l3p=%p, %d, %d,  dp=%p, %d\n",
      self->l3p, self->l3_rem, self->proto, self->dp, self->rem);
   }

static PyObject *get_size(DataObject *self) {
  if (self->type < RLT_TYPE_PKT) {
      PyErr_SetString(PyExc_ValueError,
         "Object not Packet or Data");  return NULL;
      }
   PyObject *result = PV_PyInt_FromLong((long)self->rem);
   if (result == NULL) return NULL;
   return result;
   }
set_read_only(size);

static PyObject *get_kind(DataObject *self) {
  if (self->type < RLT_TYPE_PKT) {
      PyErr_SetString(PyExc_ValueError,
         "Object not Packet or Data");  return NULL;
      }
   PyObject *result = PV_PyString_FromString(plt_kind_string(self->kind));
   if (result == NULL) return NULL;
   return result;
   }
set_read_only(kind);

static PyObject *get_type(DataObject *self) {
  if (self->type < RLT_TYPE_PKT) {
      PyErr_SetString(PyExc_ValueError,
         "Object not Packet or Data");  return NULL;
      }
   PyObject *result = PV_PyString_FromString(plt_type_string(self->type));
   if (result == NULL) return NULL;
   return result;
   }
set_read_only(type);

static PyGetSetDef Data_getsetters[] = {
   {"size",
      (getter)get_size, (setter)set_size,
      "Layer 2 header", NULL},
   {"kind",
      (getter)get_kind, (setter)set_kind,
      "Layer 2 header", NULL},
   {"type",
      (getter)get_type, (setter)set_type,
      "Layer 2 header", NULL},
   {NULL},  /* Sentinel */
   };

static PyObject *pltData_info(DataObject *self) {
   char const *k= plt_kind_string(self->kind);
   char const *t= plt_type_string(self->type);
   char s[50];
   snprintf(s, sizeof(s), "Data: type=%s, kind=%s, inrem=%d, rem=%d",
      t, k, self->l3_rem, self->rem);
   return PV_PyString_FromString(s);
   }

/* Checksum functions using ideas from libtrace/tools/tcpreplay
   (see also RFC 1071) */

uint16_t checksum(void *buffer, uint16_t len) {
   uint32_t sum = 0;
   uint16_t * buff = (uint16_t *)buffer;
   uint16_t count = len;
   while (count > 1) {
      sum += *buff++;  count = count-2;
      }
   if (count > 0) sum += *(uint8_t *)buff;
   while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
   return sum;
   }
#if 0
void hpr(void *a, int len, char *msg) {
   uint8_t *ap = (uint8_t *)a;
   int j;
   for (j = 0; j != len; ++j) printf(" %02x", ap[j]);
   printf("\n");
   }
#endif
int transport_checksum(DataObject *d, int reset_cks) {
   /* Returns 1 = cks ok, 0 = bad cks, -1 = can't compute checksum.
      NOTE: If it's correct, the computed transport checksum will be 0 */
   uint16_t save_cks;
   uint16_t *check = NULL;  uint32_t sum = 0, temp;
   libtrace_packet_t *pkt = d->data;
   uint16_t payload_len;
   uint16_t wlen = trace_get_wire_length(pkt) - fcs_decr(d->linktype);
   long clen = trace_get_capture_length(pkt);
   if (clen < wlen) return -1;  /* Not enough bytes */
   int v4 = d->ethertype != 0x86DD;
   if (d->proto == 0) {
      uint32_t remaining = d->l3_rem;  uint8_t proto = 0;
      uint8_t *l4p = NULL;
      if (d->ethertype == 0x0800)
         l4p = trace_get_payload_from_ip(
            (libtrace_ip_t *)d->l3p, &proto, &remaining);
      else if (d->ethertype == 0x86DD)
         l4p = trace_get_payload_from_ip6(
            (libtrace_ip6_t *)d->l3p, &proto, &remaining);
      d->dp = l4p;  d->rem = remaining;
      d->proto = proto;
      }
   if (v4) {
      libtrace_ip_t *ip = (libtrace_ip_t *)d->l3p;
      payload_len = ntohs(ip->ip_len)-ip->ip_hl*4;
      if (d->proto == 1) {  /* ICMP (Checksum only covers ICMP message) */
         libtrace_icmp_t *icmp_header = (libtrace_icmp_t *)d->dp;
         check = &icmp_header->checksum;
         }
      else {
         sum += checksum(&ip->ip_src.s_addr, 4);  /* 12-byte pseudo-header */
         sum += checksum(&ip->ip_dst.s_addr, 4);
         temp = htons(ip->ip_p);  sum += checksum(&temp, 2);
         temp = htons(payload_len);  sum += checksum(&temp, 2);
         if (d->proto == 6) {  /* TCP */
 	    libtrace_tcp_t *tcp_header = (libtrace_tcp_t *)d->dp;
            check = &tcp_header->check;
           }
         else if (d->proto == 17 ) {  /* UDP */
 	    libtrace_udp_t *udp_header = (libtrace_udp_t *)d->dp;
            check = &udp_header->check;
            }
	 else return -1;
         }
      }
   else {  /* v6 */
      libtrace_ip6_t *ip6 = (libtrace_ip6_t *)d->l3p;
      int hlen = (int)((uint8_t *)d->dp - (uint8_t *)d->l2p);
      payload_len = wlen-hlen;
      sum += checksum(&ip6->ip_src, 16);  /* 40-byte pseudo-header */
      sum += checksum(&ip6->ip_dst, 16);
      temp = htonl(payload_len);  sum += checksum(&temp, 4);
      temp = htons(ip6->nxt);  sum += checksum(&temp, 4);
      if (d->proto == 6) {  /* TCP */
         libtrace_tcp_t *tcp_header = (libtrace_tcp_t *)d->dp;
         check = &tcp_header->check;
         }
      else if (d->proto == 17) {  /* UDP */
         libtrace_udp_t *udp_header =  (libtrace_udp_t *)d->dp;
         check = &udp_header->check;
         }
      else if (d->proto == 58) {  /* ICMPv6 */
         libtrace_icmp6_t *icmp_header =  (libtrace_icmp6_t *)d->dp;
         check = &icmp_header->checksum;
         }
      else return -1;
      }
   save_cks = *check;  *check = 0;
   sum += checksum(d->dp, payload_len);
   while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
   sum = ~sum & 0xffff;
   if (reset_cks) { *check = sum;  return 1; }
   else { *check = save_cks;  return sum == save_cks; }
   }

static PyObject *set_checksums(DataObject *self) {
  if (!self->l3p) {
      PyObject *result = Py_None;  Py_INCREF(result);  return result;
      }
   if (self->kind != RLT_KIND_PKT) {
      PyErr_SetString(PyExc_ValueError,
         "Object didn't come from a plt Packet");  return NULL;
      }
   if (self->type < RLT_TYPE_L3) {
      PyErr_SetString(PyExc_ValueError,
         "Can't set checksums for a Layer2 object");  return NULL;
      }
   libtrace_packet_t *pkt = self->data;
   long clen = trace_get_capture_length(pkt);
   long wlen = trace_get_wire_length(pkt) - fcs_decr(self->linktype);
      /* Don't include FCS in checksum */
   if (clen < wlen) {
      PyErr_SetString(PyExc_ValueError,
         "Packet too short to set checksums");  return NULL;
      }
   int v4 = self->ethertype != 0x86DD;
   if (v4) {  /* IPv6 doesn't have a header checksum */
      libtrace_ip_t *lip = (libtrace_ip_t *)self->l3p;
      lip->ip_sum = 0;  /* Set IP checksum */
      lip->ip_sum = ~checksum(lip, lip->ip_hl*4);
      }
   int r = transport_checksum(self, 1);  /* Reset checksum */
   PyObject *result = Py_None;
   if (r >= 0) result = r ? Py_True : Py_False;
   Py_INCREF(result);  return result;
   }

static PyMethodDef Data_methods[] = {
   {"info", (PyCFunction)pltData_info, METH_NOARGS,
    "Info about a Data object" },
   {"set_checksums", (PyCFunction)set_checksums, METH_NOARGS,
    "Set Packet's IP and transport checksums"},
   {NULL}  /* Sentinel */
   };

PyTypeObject DataType = {
   PV_PyObject_HEAD_INIT
   "pltData",                   /*tp_name*/
   sizeof(DataObject),          /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)pltData_dealloc,  /*tp_dealloc*/
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
   "plt Data objects",           /* tp_doc */
   0,		                 /* tp_traverse */
   0,		                 /* tp_clear */
   0,                            /* tp_richcompare */
   0,		                 /* tp_weaklistoffset */
   0,		                 /* tp_iter */
   0,		                 /* tp_iternext */
   Data_methods,                 /* tp_methods */
   0,                            /* tp_members */
   Data_getsetters,              /* tp_getset */
   &PacketType,                  /* tp_base */
   0,                            /* tp_dict */
   0,                            /* tp_descr_get */ 
   0,                            /* tp_descr_set */
   0,                            /* tp_dictoffset */
   (initproc)pltData_init,       /* tp_init */
   0,                            /* tp_alloc */
   (newfunc)pltData_new,         /* tp_new */
   };

static PyObject *plt_version(DataObject *self) {
   return Py_BuildValue("s", PLTversion);
   }

static PyMethodDef module_methods[] = {
   {"version", (PyCFunction)plt_version, METH_NOARGS,
    "Python-libtrace version" },
   {NULL}  /* Sentinel */
   };

PyObject *plt_module=NULL;  /* The Python-Libtrace module */
PyObject *ipp_new;     /* ipp.IPprefix() function */

PyObject *datetime_datetime_obj;
PyObject* plt_exc_libtrace;

#if PYTHON3
static PyModuleDef plt_mod = {
    PyModuleDef_HEAD_INIT, "plt", "PythonLibtrace module",
            -1, module_methods, NULL, NULL, NULL, NULL
   };
#endif

#if PYTHON3
PyMODINIT_FUNC PyInit_plt(void)  {
#define RETURN return plt_module
#else
PyMODINIT_FUNC initplt(void)  {
#define RETURN return
#endif

#if PYTHON3
    plt_module = PyModule_Create(&plt_mod);
#else
    plt_module = Py_InitModule3("plt", module_methods,
      "PythonLibtrace module");
#endif
   if (plt_module == NULL) RETURN;

   if (PyType_Ready(&DataType) < 0) RETURN;

   Py_TYPE(&DataType) = &PyType_Type;

   Py_INCREF(&DataType);
   PyModule_AddObject(plt_module, "Data", (PyObject *)&DataType);

   plt_exc_libtrace = PyErr_NewException("plt.libtrace_exc", NULL, NULL);

   inittrace();  initoutputtrace();
   initpacket();
   initlayers();
   initinternet();  initip();  initip6();
   inittcp();  initudp();  initicmp();  initicmp6();

   PyObject *mainModule = PyImport_AddModule("__main__");
   PyObject *ipp_module = PyImport_ImportModule("ipp");
   PyModule_AddObject(mainModule, "ipp", ipp_module);
   PyObject *ipp_dict = PyModule_GetDict(ipp_module);
   ipp_new = PyDict_GetItemString(ipp_dict, "IPprefix");
      /* We use this to create IPprefix objects */

   PyRun_SimpleString("import datetime");
   /* Couldn't work out how to import datetime any other way !@#$%! */

   PyObject *datetime_module = PyImport_AddModule("datetime");
   PyObject *datetime_dict = PyModule_GetDict(datetime_module);
   datetime_datetime_obj = PyDict_GetItemString(datetime_dict, "datetime");
   RETURN;
   }

void quack(int which) {};  /* breakpoint for debugger */
