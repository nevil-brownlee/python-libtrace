/* 1452, Fri 14 Mar 14 (PDT)
   1140, Sat  9 Nov 13 (PST)  Mountain View

   tcp.c: RubyLibtrace, python version!

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
#include "pv.h"
#include "plt.h"

static void tcp_dealloc(PyObject *self) {
   self->ob_type->tp_free((PyObject *)self);
   }

static PyObject *tcp_new(PyTypeObject *type, PyObject *args) {
   DataObject *arg=NULL;  void *data, *l3p, *l4p = NULL;
   uint32_t l3_rem, rem;  uint8_t proto;  int ethertype;
   PyArg_ParseTuple(args, "O", (PyObject *)&arg);
   if (PyObject_IsInstance((PyObject *)arg, (PyObject *)&DataType)) {
      data = arg->data;  l3p = arg->l3p;  l3_rem = arg->l3_rem;
      if (arg->type < RLT_TYPE_Internet || arg->type >= RLT_TYPE_L4) {
         PyObject *result = Py_None;  Py_INCREF(result);  return result;
         }
      else {  /* Layer 4 object */
	 l3p = arg->l3p;  l3_rem = rem = arg->rem;
         if (arg->ethertype == 0x0800)
            l4p = trace_get_payload_from_ip(
               (libtrace_ip_t *)l3p, &proto, &rem);
         else if (arg->ethertype == 0x86DD)
            l4p = trace_get_payload_from_ip6(
               (libtrace_ip6_t *)l3p, &proto, &rem);
         if (l4p && proto != 6) {  /* Not TCP transport */
            PyObject *result = Py_None;  Py_INCREF(result);  return result;
            }
         ethertype = arg->ethertype;
         }
      }
   else if (PyByteArray_CheckExact(arg)) {
      data = NULL;
      l3p = l4p = PyByteArray_AsString((PyObject *)arg);
      l3_rem = rem = (uint32_t)PyByteArray_Size((PyObject *)arg);
      ethertype = 0;
      }
   else {
      PyErr_SetString(PyExc_ValueError,
         "Not a Data, Packet or ByteArray object");  return NULL;
      }
   Py_INCREF(arg);
   DataObject *tcp_obj = plt_new_object(&TcpType,
      RLT_TYPE_TCP, RLT_KIND_CPY, data, (PyObject *)arg,
      NULL, 0, 0, ethertype, 0,  l3p, l3_rem, 6,  l4p, rem);
   // pltData_dump(tcp_obj, "*leaving plt.tcp()");  //debug
   return (PyObject *)tcp_obj;
   }

static int tcp_init(DataObject *self, PyObject *args) {
   return 0;
   }

static libtrace_tcp_t *get_tcp(DataObject *op, int x) {
   if (op->proto != 6) {
      PyErr_SetString(PyExc_ValueError, "Expected a TCP object");
         return NULL;
      }
   if (op->rem < x) return NULL;
   return (libtrace_tcp_t *)op->dp;
   }

static PyObject *get_src_port(DataObject *self, void *closure) {
   libtrace_tcp_t *ltcp = get_tcp(self, 2);
   if (!ltcp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for src_port");  return NULL;
      }
   return PV_PyInt_FromLong((long)ntohs(ltcp->source));
   }
set_read_only(src_port);

static PyObject *get_dst_port(DataObject *self, void *closure) {
   libtrace_tcp_t *ltcp = get_tcp(self, 4);
   if (!ltcp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for dst_port");  return NULL;
      }
   return PV_PyInt_FromLong((long)ntohs(ltcp->dest));
   }
set_read_only(dst_port);

static PyObject *get_seq_nbr(DataObject *self, void *closure) {
   libtrace_tcp_t *ltcp = get_tcp(self, 8);
   if (!ltcp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for seq_nbr");  return NULL;
      }
   return PyLong_FromUnsignedLong((unsigned long)ntohl(ltcp->seq));
   }
set_read_only(seq_nbr);

static PyObject *get_ack_nbr(DataObject *self, void *closure) {
   libtrace_tcp_t *ltcp = get_tcp(self, 12);
   if (!ltcp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for ack_nbr");  return NULL;
      }
   return PyLong_FromUnsignedLong((unsigned long)ntohl(ltcp->ack_seq));
   }
set_read_only(ack_nbr);

static PyObject *get_doff(DataObject *self, void *closure) {
   libtrace_tcp_t *ltcp = get_tcp(self, 13);
   if (!ltcp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for doff");  return NULL;
      }
   uint8_t *hp = (uint8_t *)ltcp;
   return PV_PyInt_FromLong((long)hp[12] >> 4);
   }
set_read_only(doff);

static PyObject *get_flags(DataObject *self, void *closure) {
   libtrace_tcp_t *ltcp = get_tcp(self, 14);
   if (!ltcp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for flags");  return NULL;
      }
   uint16_t *t16p = (uint16_t *)ltcp;
   return PyLong_FromUnsignedLong((unsigned long)ntohs(t16p[6]) & 0x0FFF);
   }
set_read_only(flags);

static PyObject *get_urg_flag(DataObject *self, void *closure) {
   libtrace_tcp_t *ltcp = get_tcp(self, 14);
   if (!ltcp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for urg_flag");  return NULL;
      }
   uint8_t *fp = (uint8_t *)ltcp;
   PyObject *result = (fp[13] & 0x20) != 0 ? Py_True : Py_False;
   Py_INCREF(result);  return result; 
   }
set_read_only(urg_flag);

static PyObject *get_ack_flag(DataObject *self, void *closure) {
   libtrace_tcp_t *ltcp = get_tcp(self, 14);
   if (!ltcp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for ack_flag");  return NULL;
      }
   uint8_t *fp = (uint8_t *)ltcp;
   PyObject *result = (fp[13] & 0x10) != 0 ? Py_True : Py_False;
   Py_INCREF(result);  return result; 
   }
set_read_only(ack_flag);

static PyObject *get_psh_flag(DataObject *self, void *closure) {
   libtrace_tcp_t *ltcp = get_tcp(self, 14);
   if (!ltcp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for psh_flag");  return NULL;
      }
   uint8_t *fp = (uint8_t *)ltcp;
   PyObject *result = (fp[13] & 0x08) != 0 ? Py_True : Py_False;
   Py_INCREF(result);  return result; 
   }
set_read_only(psh_flag);

static PyObject *get_rst_flag(DataObject *self, void *closure) {
   libtrace_tcp_t *ltcp = get_tcp(self, 14);
   if (!ltcp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for rst_flag");  return NULL;
      }
   uint8_t *fp = (uint8_t *)ltcp;
   PyObject *result = (fp[13] & 0x04) != 0 ? Py_True : Py_False;
   Py_INCREF(result);  return result; 
   }
set_read_only(rst_flag);

static PyObject *get_syn_flag(DataObject *self, void *closure) {
   libtrace_tcp_t *ltcp = get_tcp(self, 14);
   if (!ltcp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for syn_flag");  return NULL;
      }
   uint8_t *fp = (uint8_t *)ltcp;
   PyObject *result = (fp[13] & 0x02) != 0 ? Py_True : Py_False;
   Py_INCREF(result);  return result; 
   }
set_read_only(syn_flag);

static PyObject *get_fin_flag(DataObject *self, void *closure) {
   libtrace_tcp_t *ltcp = get_tcp(self, 14);
   if (!ltcp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for fin_flag");  return NULL;
      }
   uint8_t *fp = (uint8_t *)ltcp;
   PyObject *result = (fp[13] & 0x01) != 0 ? Py_True : Py_False;
   Py_INCREF(result);  return result; 
   }
set_read_only(fin_flag);

static PyObject *get_window(DataObject *self, void *closure) {
   libtrace_tcp_t *ltcp = get_tcp(self, 16);
   if (!ltcp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for window");  return NULL;
      }
   return PyLong_FromUnsignedLong((unsigned long)ntohs(ltcp->window));
   }
set_read_only(window);

static PyObject *tcp_get_checksum(DataObject *self, void *closure) {
   libtrace_tcp_t *ltcp = get_tcp(self, 18);
   if (!ltcp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for tcp checksum");  return NULL;
      }
   return PyLong_FromUnsignedLong((unsigned long)ntohs(ltcp->check));
   }
// set_read_only(checksum);
static int set_checksum(DataObject *self,
      PyObject *value, void *closure) {
   if (self->kind != RLT_KIND_PKT) {
      PyErr_SetString(PyExc_ValueError,
         "Object didn't come from a plt Packet");  return -1;
      }
   libtrace_tcp_t *ltcp = get_tcp(self, 18); 
   if (!ltcp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for tcp checksum");
      return -1;
      }
   if (!PV_PyInt_Check(value)) {
      PyErr_SetString(PyExc_TypeError,
         "Expected integer or None");  return -1;
      }
   long cks_v = PV_PyInt_AsLong(value);
   if (cks_v < 0 || cks_v > 0xFFFF) {
      PyErr_SetString(PyExc_ValueError,
         "Checksum not 16-bit unsigned integer");  return -1;
      }
   ltcp->check = ntohs((uint16_t)cks_v);
   return 0;
   }

static PyObject *get_urg_ptr(DataObject *self, void *closure) {
   libtrace_tcp_t *ltcp = get_tcp(self, 20);
   if (!ltcp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for urg_ptr");  return NULL;
      }
   return PyLong_FromUnsignedLong((unsigned long)ntohs(ltcp->urg_ptr));
   }
set_read_only(urg_ptr);

static PyObject *tcp_get_payload(DataObject *self, void *closure) {
   libtrace_tcp_t *ltcp = get_tcp(self, 20);
   if (!ltcp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for tcp_payload");  return NULL;
      }
   uint8_t *hp = (uint8_t *)ltcp;
   int tcp_len = (hp[12] >> 4)*4;  /* Bytes */
   if (self->rem < tcp_len) {
      PyErr_SetString(PyExc_ValueError,
         "Captured packet too short for tcp_payload");  return NULL;
      }
   if (self->rem == tcp_len) {  /* No payload */
      PyObject *result = Py_None;  Py_INCREF(result);  return result; 
      }
   Py_INCREF(self);
   DataObject *pld_obj = plt_new_object(&TransportType,
      RLT_TYPE_L5, RLT_KIND_CPY, NULL, (PyObject *)self,
      self->l2p, self->l2_rem, self->linktype, self->ethertype, self->vlan_tag,
      self->l3p, self->l3_rem, 6,  &hp[tcp_len], self->rem-tcp_len);
   // pltData_dump(pld_obj, "*leaving tcp.tcp_get_payload(pld_obj)");  //debug
   return (PyObject *)pld_obj;
   }
set_read_only(payload);

static PyGetSetDef TCP_getseters[] = {
   {"src_port",
      (getter)get_src_port, (setter)set_src_port,
      "TCP source port", NULL},
   {"dst_port",
      (getter)get_dst_port, (setter)set_dst_port,
      "TCP dest port", NULL},
   {"seq_nbr",
      (getter)get_seq_nbr, (setter)set_seq_nbr,
      "TCP sequence nbr", NULL},
   {"ack_nbr",
      (getter)get_ack_nbr, (setter)set_ack_nbr,
      "TCP acknowledgement nbr", NULL},
   {"doff",
      (getter)get_doff, (setter)set_doff,
      "TCP data ofset (header length)", NULL},
   {"flags",
      (getter)get_flags, (setter)set_flags,
      "TCP flags field", NULL},
   {"urg_flag",
      (getter)get_urg_flag, (setter)set_urg_flag,
      "TCP urgent flag", NULL},
   {"ack_flag",
      (getter)get_ack_flag, (setter)set_ack_flag,
      "TCP ACK flag", NULL},
   {"psh_flag",
      (getter)get_psh_flag, (setter)set_psh_flag,
      "TCP Push flag", NULL},
   {"rst_flag",
      (getter)get_rst_flag, (setter)set_rst_flag,
      "TCP Reset flag", NULL},
   {"syn_flag",
      (getter)get_syn_flag, (setter)set_syn_flag,
      "TCP SYN flag", NULL},
   {"fin_flag",
      (getter)get_fin_flag, (setter)set_fin_flag,
      "TCP FIN flag", NULL},
   {"window",
      (getter)get_window, (setter)set_window,
      "TCP window size", NULL},
   {"checksum",
      (getter)tcp_get_checksum, (setter)set_checksum,
      "TCP checksum", NULL},
   {"urg_ptr",
      (getter)get_urg_ptr, (setter)set_urg_ptr,
      "TCP Urgent pointer", NULL},
   {"payload",
      (getter)tcp_get_payload, (setter)set_payload,
      "TCP payload", NULL},
   {NULL},  /* Sentinel */
   };

static PyMethodDef tcp_methods[] = {
   {NULL}  /* Sentinel */
   };

PyTypeObject TcpType = {
   PV_PyObject_HEAD_INIT
   "TcpObject",                 /*tp_name*/
   sizeof(DataObject),          /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)tcp_dealloc,     /*tp_dealloc*/
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
   "PythonLibtrace TCP",        /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   tcp_methods,                 /* tp_methods */
   0,                           /* tp_members */
   TCP_getseters,               /* tp_getset */
   &InternetType,               /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */ 
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)tcp_init,          /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)tcp_new,            /* tp_new */
   };


void inittcp(void) {
   if (PyType_Ready(&TcpType) < 0) return;

   Py_TYPE(&TcpType) = &PyType_Type;

   Py_INCREF(&TcpType);
   PyModule_AddObject(plt_module, "tcp", (PyObject *)&TcpType);
   }
