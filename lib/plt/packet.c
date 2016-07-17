/* 1452, Fri 14 Mar 14 (PDT)
   1837, Wed 23 Oct 13 (NZDT)

   packet.c: RubyLibtrace, python version!

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

static void pltPacket_dealloc(PyObject *self) {
   PV_free_self;
   }

static PyObject *pltPacket_new(PyObject *type) {
   DataObject *self = (DataObject *)DataType.tp_alloc(&DataType, 0);
   self->kind = RLT_KIND_PKT;  self->type = RLT_TYPE_PKT;
   return (PyObject *)self;
   }

static int pltPacket_init(DataObject *self) {
   return 0;
   }

#define check_pkt(d, failv) \
   if (d->kind != RLT_KIND_PKT) { \
      PyErr_SetString(PyExc_ValueError, \
         "Object didn't come from a plt Packet");  return failv; \
      }

#define check_data(d, failv) \
   if (d->type < RLT_TYPE_L2) { \
      PyErr_SetString(PyExc_ValueError, \
         "Expected a plt Data object");  return failv; \
      }

static PyObject *plt_get_data(DataObject *self, void *closure) {
   uint8_t *dp;  int size;
   if (!PyObject_IsInstance((PyObject *)self, (PyObject *)&DataType)) {
      PyErr_SetString(PyExc_ValueError,
         "Object not Packet or Data");  return NULL;
      }
   if (self->type == RLT_TYPE_PKT) {
      dp = self->l2p;  size = self->l2_rem;
      }
   else { dp = self->dp;  size = self->rem; }
   PyObject *result;
   if (size < 0) {  /* Zero-length ByteArray is OK */
      result = Py_None;  Py_INCREF(result);  return result;
      }
   result = PyByteArray_FromStringAndSize((char *)dp, size);
   if (result == NULL) return NULL;
   return result;
   }
static int set_data(DataObject *self, PyObject *value, void *closure) {
   if (!PyObject_IsInstance((PyObject *)self, (PyObject *)&DataType)) {
      PyErr_SetString(PyExc_ValueError,
         "Object not Packet or Data");  return -1;
      }
   if (!PyByteArray_CheckExact(value)) {
      PyErr_SetString(PyExc_ValueError,
         "data not ByteArray");  return -1;
      }
   uint8_t *dp;  int size;
   if (self->type == RLT_TYPE_PKT) {
      dp = self->l2p;  size = self->l2_rem;
      }
   else { dp = self->dp;  size = self->rem; }
   long vsize = PyByteArray_GET_SIZE(value);
   if (size < vsize) {
      PyErr_SetString(PyExc_ValueError,
         "Replacement data can't be longer than orignal");
      return -1;
      }
   char *vp = PyByteArray_AS_STRING(value);
   memcpy(dp, vp, vsize);
   return 0;
   }

static PyObject *plt_get_layer2(DataObject *self) {
   check_pkt(self, NULL);
   DataObject *l2_obj = plt_new_object(&Layer2Type,
      RLT_TYPE_L2, RLT_KIND_PKT, self->data, Py_None,
      self->l2p, self->l2_rem,
      self->linktype, self->ethertype, self->vlan_tag,
      NULL, 0, 0,  self->l2p, self->l2_rem);
   // pltData_dump(l2_obj, "*leaving get_layer2()");  //debug
   return (PyObject *)l2_obj;
   }
set_read_only(layer2);

static PyObject *plt_get_layer3(DataObject *self) {
   check_pkt(self, NULL);
   DataObject *l3_obj = plt_new_object(&Layer3Type,
      RLT_TYPE_L3, RLT_KIND_PKT, self->data, Py_None,
      self->l2p, self->l2_rem,
      self->linktype, self->ethertype, self->vlan_tag,
      self->l3p, self->l3_rem, 0,  self->l3p, self->l3_rem);
   // pltData_dump(l3_obj, "*leaving get_layer3()");  //debug
   return (PyObject *)l3_obj;
}
set_read_only(layer3);

static PyObject *plt_get_transport(DataObject *self) {
   check_pkt(self, NULL);
   uint8_t proto, *trans;  uint32_t remaining = self->l3_rem;
   trans = (uint8_t *)trace_get_transport(self->data, &proto, &remaining);
   if (trans) {
      DataObject *tr_obj = plt_new_object(&TransportType,
         RLT_TYPE_L4, RLT_KIND_PKT, self->data, Py_None,
         self->l2p, self->l2_rem,
         self->linktype, self->ethertype, self->vlan_tag,
         self->l3p, self->l3_rem, proto,  trans, remaining);
      // pltData_dump(tr_obj, "*leaving get_transport()");  //debug
      return (PyObject *)tr_obj;
      }
     PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }
set_read_only(transport);

static PyObject *plt_get_ip(DataObject *self) {
   check_pkt(self, NULL);
   if (self->ethertype == 0x0800) {
      DataObject *ip_obj = plt_new_object(&IpType,
         RLT_TYPE_IP, RLT_KIND_PKT, self->data, Py_None,
         self->l2p, self->l2_rem,
         self->linktype, self->ethertype, self->vlan_tag,
         self->l3p, self->l3_rem, 0,  self->l3p, self->l3_rem);
      // pltData_dump(ip_obj, "*leaving get_ip()");  //debug
      return (PyObject *)ip_obj;
      }
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }
set_read_only(ip);

static PyObject *plt_get_ip6(DataObject *self) {
   check_pkt(self, NULL);
   if (self->ethertype == 0x86DD) {
      DataObject *ip6_obj = plt_new_object(&Ip6Type,
         RLT_TYPE_IP6, RLT_KIND_PKT, self->data, Py_None,
         self->l2p, self->l2_rem,
         self->linktype, self->ethertype, self->vlan_tag,
         self->l3p, self->l3_rem, 0,  self->l3p, self->l3_rem);
      // pltData_dump(ip6_obj, "*leaving get_ip6()");  //debug
      return (PyObject *)ip6_obj;
      }
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }
set_read_only(ip6);

static PyObject *plt_get_tcp(DataObject *self) {
   uint32_t remaining = self->l3_rem;  uint8_t proto;
   uint8_t *l4p = NULL;
   if (self->ethertype == 0x0800)
      l4p = trace_get_payload_from_ip(
         (libtrace_ip_t *)self->l3p, &proto, &remaining);
   else if (self->ethertype == 0x86DD)
      l4p = trace_get_payload_from_ip6(
         (libtrace_ip6_t *)self->l3p, &proto, &remaining);
   if (l4p && proto == 6) {
      if (remaining >= 4) {  /* Enough for source port */
    	 DataObject *tcp_obj = plt_new_object(&TcpType,
            RLT_TYPE_TCP, self->kind, self->data, Py_None,
            self->l2p, self->l2_rem,
            self->linktype, self->ethertype, self->vlan_tag,
            self->l3p, self->l3_rem, 6,  l4p, remaining);
         // pltData_dump(tcp_obj, "*leaving plt_get_tcp()");  //debug
         return (PyObject *)tcp_obj;
         }
      }
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }
set_read_only(tcp);

static PyObject *plt_get_udp(DataObject *self) {
   uint32_t remaining = self->l3_rem;  uint8_t proto;
   uint8_t *l4p = NULL;
   if (self->ethertype == 0x0800)
      l4p = trace_get_payload_from_ip(
         (libtrace_ip_t *)self->l3p, &proto, &remaining);
   else if (self->ethertype == 0x86DD)
      l4p = trace_get_payload_from_ip6(
         (libtrace_ip6_t *)self->l3p, &proto, &remaining);
   if (l4p && proto == 17) {
      if (remaining >= 4) {  /* Enough for source port */
    	 DataObject *udp_obj = plt_new_object(&UdpType,
            RLT_TYPE_UDP, self->kind, self->data, Py_None,
            self->l2p, self->l2_rem,
            self->linktype, self->ethertype, self->vlan_tag,
            self->l3p, self->l3_rem, 17,  l4p, remaining);
         // pltData_dump(udp_obj, "*leaving get_udp()");  //debug
         return (PyObject *)udp_obj;
         }
      }
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }
set_read_only(udp);

static PyObject *plt_get_icmp(DataObject *self) {
   uint32_t remaining = self->l3_rem;  uint8_t proto;
   uint8_t *l4p = NULL;
   if (self->ethertype == 0x0800) l4p = trace_get_payload_from_ip(
         (libtrace_ip_t *)self->l3p, &proto, &remaining);
   if (l4p && proto == 1) {
      if (remaining >= 1) {  /* Enough for ICMP type */
    	 DataObject *icmp_obj = plt_new_object(&IcmpType,
            RLT_TYPE_ICMP, self->kind, self->data, Py_None,
            self->l2p, self->l2_rem,
            self->linktype, self->ethertype, self->vlan_tag,
            self->l3p, self->l3_rem, 1,  l4p, remaining);
         // pltData_dump(imcp_obj, "*leaving get_icmp()");  //debug
         return (PyObject *)icmp_obj;
         }
      }
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }
set_read_only(icmp);

static PyObject *plt_get_icmp6(DataObject *self) {
   uint32_t remaining = self->l3_rem;  uint8_t proto;
   uint8_t *l4p = NULL;
   if (self->ethertype == 0x86DD)
      l4p = trace_get_payload_from_ip6(
         (libtrace_ip6_t *)self->l3p, &proto, &remaining);
   if (l4p && proto == 58) {
      if (remaining >= 1) {  /* Enough for ICMP6 type */
    	 DataObject *obj = plt_new_object(&Icmp6Type,
            RLT_TYPE_ICMP6, self->kind, self->data, Py_None,
            self->l2p, self->l2_rem,
            self->linktype, self->ethertype, self->vlan_tag,
            self->l3p, self->l3_rem, 58,  l4p, remaining);
         // pltData_dump(obj, "*leaving get_icmp6()");  //debug
         return (PyObject *)obj;
         }
      }
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }
set_read_only(icmp6);

static PyObject *plt_get_tcp_payload(DataObject *self) {
   uint32_t remaining = self->l3_rem;  uint8_t proto;
   uint8_t *l4p = NULL;
   if (self->ethertype == 0x0800)
      l4p = trace_get_payload_from_ip(
         (libtrace_ip_t *)self->l3p, &proto, &remaining);
   else if (self->ethertype == 0x86DD)
      l4p = trace_get_payload_from_ip6(
         (libtrace_ip6_t *)self->l3p, &proto, &remaining);
   if (l4p && proto == 6) {
      void *payload = trace_get_payload_from_tcp(
         (libtrace_tcp_t *)l4p, &remaining);
      if (payload) {
         DataObject *payload_obj = plt_new_object(&TransportType,
            RLT_TYPE_L5, self->kind, self->data, Py_None,
            self->l2p, self->l2_rem,
            self->linktype, self->ethertype, self->vlan_tag,
            self->l3p, self->l3_rem, self->proto,  payload, remaining);
         // pltData_dump(payload_obj, "*leaving get_tcp_payload()");
         return (PyObject *)payload_obj;
         }
      }
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }
set_read_only(tcp_payload);

static PyObject *plt_get_udp_payload(DataObject *self) {
   uint32_t remaining = self->l3_rem;  uint8_t proto;
   uint8_t *l4p = NULL;
   PyObject *result;
   if (self->ethertype == 0x0800)
      l4p = trace_get_payload_from_ip(
         (libtrace_ip_t *)self->l3p, &proto, &remaining);
   else if (self->ethertype == 0x86DD)
      l4p = trace_get_payload_from_ip6(
         (libtrace_ip6_t *)self->l3p, &proto, &remaining);
   if (l4p && proto == 17) {
      if (remaining >= 16) {  /* No options in UDP header */
         void *payload = trace_get_payload_from_udp(
            (libtrace_udp_t *)l4p, &remaining);
         if (payload) {
	    DataObject *payload_obj = plt_new_object(&TransportType,
               RLT_TYPE_L5, self->kind, self->data, Py_None,
               self->l2p, self->l2_rem,
               self->linktype, self->ethertype, self->vlan_tag,
               self->l3p, self->l3_rem, self->proto, payload, remaining);
            // pltData_dump(payload_obj, "*leaving get_udp_payload()");
	    return (PyObject *)payload_obj;
	    }
         }
      }
   result = Py_None;  Py_INCREF(result);  return result;
   }
set_read_only(udp_payload);

static PyObject *plt_get_ethertype(DataObject *self) {
   PyObject *result = PV_PyInt_FromLong((long)self->ethertype);
   if (result == NULL) return NULL;
   return result;
   }
set_read_only(ethertype);

static PyObject *plt_get_linktype(DataObject *self) {
   PyObject *result = PV_PyInt_FromLong((long)self->linktype);
   if (result == NULL) return NULL;
   return result;
   }
set_read_only(linktype);

static PyObject *plt_get_proto(DataObject *self) {
   PyObject *result = PV_PyInt_FromLong((long)self->proto);
   if (result == NULL) return NULL;
   return result;
   }
set_read_only(proto);

static PyObject *plt_get_vlan_id(DataObject *self) {
   PyObject *result = PV_PyInt_FromLong((long)(self->vlan_tag & 0x0FFF));
   if (result == NULL) return NULL;
   return result;
   }
set_read_only(vlan_id);

static PyObject *plt_get_time(DataObject *self) {
   check_pkt(self, NULL);
   libtrace_packet_t *pkt = self->data;
   struct timeval tv = trace_get_timeval(pkt);
   unsigned long s = tv.tv_sec, us = tv.tv_usec;
   double dt = (double)s + (double)us/1000000.0;
   PyObject *pd = PyFloat_FromDouble(dt);
   return PyObject_CallMethod(
      datetime_datetime_obj, "fromtimestamp", "(O)", pd);

   }
set_read_only(time);

static PyObject *plt_get_seconds(DataObject *self) {
   check_pkt(self, NULL);
   libtrace_packet_t *pkt = self->data;
   double dt = trace_get_seconds(pkt);  /* Originally used trage_get_timeval */
   return PyFloat_FromDouble(dt);
   }
set_read_only(seconds);

static PyObject *plt_get_ts_sec(DataObject *self) {
   check_pkt(self, NULL);
   libtrace_packet_t *pkt = self->data;
   struct timeval tv = trace_get_timeval(pkt);
   unsigned long s = tv.tv_sec;
   return PyLong_FromUnsignedLong(s);
   }
set_read_only(ts_sec);

static PyObject *plt_get_erf_time(DataObject *self) {
   check_pkt(self, NULL);
   libtrace_packet_t *pkt = self->data;
   unsigned long long erf_t = trace_get_erf_timestamp(pkt);
   return PyLong_FromUnsignedLongLong(erf_t);
   }
set_read_only(erf_time);

static PyObject *plt_get_wire_len(DataObject *self) {
   check_pkt(self, NULL);
   libtrace_packet_t *pkt = self->data;
   long wlen = trace_get_wire_length(pkt);  /* includes FCS!  17 May 14 */
   PyObject *result = PV_PyInt_FromLong((long)wlen);
   if (result == NULL) return NULL;
   return result;
   }
set_read_only(wire_len);

static PyObject *plt_get_capture_len(DataObject *self) {
   check_pkt(self, NULL);
   libtrace_packet_t *pkt = self->data;
   long clen = trace_get_capture_length(pkt);
   PyObject *result = PV_PyInt_FromLong((long)clen);
   if (result == NULL) return NULL;
   return result;
   }
set_read_only(capture_len);

static PyObject *plt_get_direction(DataObject *self) {
   check_pkt(self, NULL);
   libtrace_packet_t *pkt = self->data;
   libtrace_direction_t p_dir = trace_get_direction(pkt);
   PyObject *result = PV_PyInt_FromLong((long)p_dir);
   if (result == NULL) return NULL;
   return result;
   }
set_read_only(direction);

static PyObject *plt_apply_filter(DataObject *self, PyObject *args) {
   FilterObject *p_flt = NULL;
   if (!PyArg_ParseTuple(args, "O:plt_apply_filter", &p_flt)) {
      PyErr_SetString(PyExc_SystemError, "Expected a Filter object");
      return NULL;
      }
   if (!PyObject_IsInstance((PyObject *)p_flt, (PyObject *)&FilterType)) {
      PyErr_SetString(PyExc_SystemError, "Expected a Filter object");
      return NULL;
      }
   //pltData_dump(self, "*plt_apply_filter()");  //debug
   if ( self->type != RLT_TYPE_PKT) {
      PyErr_SetString(PyExc_ValueError, "Not a Packet object");
      return NULL;
      }
   struct libtrace_packet_t *pkt = (libtrace_packet_t *)self->data;
   int r = trace_apply_filter(p_flt->flt, pkt);
   PyObject *result;
   if (r > 0) result = Py_True;
   else if (r == 0) result = Py_False;
   else result = Py_None;
   Py_INCREF(result);  return result;
   }

static PyObject *plt_py_data_dump(DataObject *self) {
   pltData_dump(self, "* plt DataObject");
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }

static PyMethodDef Packet_methods[] = {
   {"apply_filter", (PyCFunction)plt_apply_filter, METH_VARARGS,
      "Test whether packet matches a filter"},
   {"dump", (PyCFunction)plt_py_data_dump, METH_NOARGS,
      "Python DataObject dump"},
   {NULL}  /* Sentinel */
   };

static PyGetSetDef Packet_getseters[] = {
   {"data",
      (getter)plt_get_data, (setter)set_data,
      "header (and following) bytes of object", NULL},
   {"layer2",
      (getter)plt_get_layer2, (setter)set_layer2,
      "Layer 2 header", NULL},
   {"layer3",
      (getter)plt_get_layer3, (setter)set_layer3,
      "Layer 3 header", NULL},
   {"transport",
      (getter)plt_get_transport, (setter)set_transport,
      "Layer 2 header", NULL},
   {"ip",
      (getter)plt_get_ip, (setter)set_ip,
      "IPv4 header", NULL},
   {"ip6",
      (getter)plt_get_ip6, (setter)set_ip6,
      "IPv6 header", NULL},
   {"tcp",
      (getter)plt_get_tcp, (setter)set_tcp,
      "TCP header", NULL},
   {"udp",
    (getter)plt_get_udp, (setter)set_udp,
      "UDP header", NULL},
   {"tcp_payload",
      (getter)plt_get_tcp_payload, (setter)set_tcp_payload,
      "TCP payload", NULL},
   {"udp_payload",
    (getter)plt_get_udp_payload, (setter)set_udp_payload,
      "UDP payload", NULL},
   {"icmp",
    (getter)plt_get_icmp, (setter)set_icmp,
      "ICMP header", NULL},
   {"icmp6",
    (getter)plt_get_icmp6, (setter)set_icmp6,
      "ICMP6 header", NULL},

   {"ethertype", (getter)plt_get_ethertype, (setter)set_ethertype,
      "packet's ethertype", NULL},
   {"linktype", (getter)plt_get_linktype, (setter)set_linktype,
      "packet's libtrace TRACE_TYPE", NULL},
   {"proto", (getter)plt_get_proto, (setter)set_proto,
      "packet's transport protocol", NULL},
   {"vlan_id", (getter)plt_get_vlan_id, (setter)set_vlan_id,
      "vlan id fi a protocol 8100 packet", NULL},

   {"time", (getter)plt_get_time, (setter)set_time,
      "arival time (datetime)", NULL},
   {"seconds", (getter)plt_get_seconds, (setter)set_seconds,
      "arival time (float)", NULL},
   {"ts_sec", (getter)plt_get_ts_sec, (setter)set_ts_sec,
      "arival time (Unix seconds)", NULL},
   {"erf_time", (getter)plt_get_erf_time, (setter)set_erf_time,
      "arival time (DAG ERF)", NULL},
   {"wire_len", (getter)plt_get_wire_len, (setter)set_wire_len,
      "packet size on wire", NULL},
   {"direction", (getter)plt_get_direction, (setter)set_direction,
      "packet direction for multi-interface trace types", NULL},
   {"capture_len", (getter)plt_get_capture_len, (setter)set_capture_len,
      "number of bytes captured", NULL},
   {NULL},  /* Sentinel */
   };

PyTypeObject PacketType = {
   PV_PyObject_HEAD_INIT
   "Packet",                  /*tp_name*/
   sizeof(DataObject),      /*tp_basicsize*/
   0,                         /*tp_itemsize*/
   (destructor)pltPacket_dealloc,  /*tp_dealloc*/
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
   "Python-libtrace Packet",  /* tp_doc */
   0,		              /* tp_traverse */
   0,		              /* tp_clear */
   0,                         /* tp_richcompare */
   0,		              /* tp_weaklistoffset */
   0,		              /* tp_iter */
   0,		              /* tp_iternext */
   Packet_methods,            /* tp_methods */
   0,                         /* tp_members */
   Packet_getseters,          /* tp_getset */
   0,                         /* tp_base */
   0,                         /* tp_dict */
   0,                         /* tp_descr_get */ 
   0,                         /* tp_descr_set */
   0,                         /* tp_dictoffset */
   (initproc)pltPacket_init,  /* tp_init */
   0,                         /* tp_alloc */
   (newfunc)pltPacket_new,    /* tp_new */
   };


void initpacket(void) {
   if (PyType_Ready(&PacketType) < 0) return;

   Py_TYPE(&PacketType) = &PyType_Type;

   Py_INCREF(&PacketType);
   PyModule_AddObject(plt_module, "packet", (PyObject *)&PacketType);

   PyObject *out_v = PV_PyInt_FromLong((long)TRACE_DIR_OUTGOING);
   if (out_v == NULL) return;  Py_INCREF(out_v);
   PyModule_AddObject(plt_module, "TRACE_DIR_OUTGOING", out_v);

   PyObject *in_v = PV_PyInt_FromLong((long)TRACE_DIR_INCOMING);
   if (in_v == NULL) return;  Py_INCREF(in_v);
   PyModule_AddObject(plt_module, "TRACE_DIR_INCOMING", in_v);

   PyObject *other_v = PV_PyInt_FromLong((long)TRACE_DIR_OTHER);
   if (other_v == NULL) return;  Py_INCREF(other_v);
   PyModule_AddObject(plt_module, "TRACE_DIR_OTHER", other_v);
   }
