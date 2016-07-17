/* 1452, Fri 14 Mar 14 (PDT)
   0530, Tue 12 Nov 13 (AEDT)  United 863

   udp.c: RubyLibtrace, python version!

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

static void udp_dealloc(PyObject *self) {
   self->ob_type->tp_free((PyObject *)self);
   }

static PyObject *udp_new(PyTypeObject *type, PyObject *args) {
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
         if (l4p && proto != 17) {  /* Not UDP transport */
            PyObject *result = Py_None;  Py_INCREF(result);  return result;
            }
         ethertype = arg->ethertype;
         }
      }
   else if (PyByteArray_CheckExact(arg)) {
      l3p = data = NULL;  l3_rem = 0;
      l4p = PyByteArray_AsString((PyObject *)arg);
      rem = (uint32_t)PyByteArray_Size((PyObject *)arg);
      ethertype = 0;
      }
   else {
      PyErr_SetString(PyExc_ValueError,
         "Not a Data, Packet or ByteArray object");  return NULL;
      }
   Py_INCREF(arg);
   DataObject *udp_obj = plt_new_object(&UdpType,
      RLT_TYPE_UDP, RLT_KIND_CPY, data, (PyObject *)arg,
      NULL, 0, 0, ethertype, 0,  l3p, l3_rem, 17,  l4p, rem);
   // pltData_dump(udp_obj, "*leaving plt.udp()");  //debug
   return (PyObject *)udp_obj;
   }

static int udp_init(DataObject *self, PyObject *args) {
   return 0;
   }

static libtrace_udp_t *get_udp(DataObject *op, int x) {
   if (op->proto != 17) {
      PyErr_SetString(PyExc_ValueError, "Expected a UDP object");
         return NULL;
      }
   if (op->rem < x) return NULL;
   libtrace_udp_t *ludp = op->dp;
   return ludp;
   }

static PyObject *get_src_port(DataObject *self, void *closure) {
   libtrace_udp_t *ludp = get_udp(self, 2);
   if (!ludp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for src_port");  return NULL;
      }
   return PV_PyInt_FromLong((long)ntohs(ludp->source));
   }
set_read_only(src_port);

static PyObject *get_dst_port(DataObject *self, void *closure) {
   libtrace_udp_t *ludp = get_udp(self, 4);
   if (!ludp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for dst_port");  return NULL;
      }
   return PV_PyInt_FromLong((long)ntohs(ludp->dest));
   }
set_read_only(dst_port);

static PyObject *get_len(DataObject *self, void *closure) {
   libtrace_udp_t *ludp = get_udp(self, 6);
   if (!ludp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for len");  return NULL;
      }
   return PyLong_FromUnsignedLong((unsigned long)ntohs(ludp->len));
   }
set_read_only(len);

static PyObject *get_checksum(DataObject *self, void *closure) {
   libtrace_udp_t *ludp = get_udp(self, 8);
   if (!ludp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for checksum");  return NULL;
      }
   return PyLong_FromUnsignedLong((unsigned long)ntohs(ludp->check));
   }
static int set_checksum(DataObject *self,
      PyObject *value, void *closure) {
   if (self->kind != RLT_KIND_PKT) {
      PyErr_SetString(PyExc_ValueError,
         "Object didn't come from a plt Packet");  return -1;
      }
   libtrace_udp_t *ludp = get_udp(self, 8); 
   if (!ludp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for udp checksum");
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
   ludp->check = ntohs((uint16_t)cks_v);
   return 0;
   }

static PyObject *udp_get_payload(DataObject *self, void *closure) {
   libtrace_udp_t *ludp = get_udp(self, 8);
   if (!ludp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for udp payload");  return NULL;
      }
   uint8_t *up = (uint8_t *)ludp;
   int udp_len = 8;  /* Bytes */
   if (self->rem < udp_len) {
      PyErr_SetString(PyExc_ValueError,
         "Captured packet too short for udp payload");  return NULL;
      }
   if (self->rem == udp_len) {
      PyObject *result = Py_None;  Py_INCREF(result);  return result; 
      }
   Py_INCREF(self);
   DataObject *pld_obj = plt_new_object(&TransportType,
      RLT_TYPE_L5, RLT_KIND_CPY, NULL, (PyObject *)self,
      self->l2p, self->l2_rem, self->linktype, self->ethertype, self->vlan_tag,
      self->l3p, self->l3_rem, 17,  &up[udp_len], self->rem-udp_len);
   // pltData_dump(pld_obj, "*leaving tcp.udp_get_payload(pld_obj)");  //debug
   return (PyObject *)pld_obj;
   }
set_read_only(payload);

static PyGetSetDef UDP_getseters[] = {
   {"src_port",
      (getter)get_src_port, (setter)set_src_port,
      "UDP source port", NULL},
   {"dst_port",
      (getter)get_dst_port, (setter)set_dst_port,
      "UDPP dest port", NULL},
   {"len",
      (getter)get_len, (setter)set_len,
      "UDP length", NULL},
   {"checksum",
      (getter)get_checksum, (setter)set_checksum,
      "UDP checksum", NULL},
   {"payload",
      (getter)udp_get_payload, (setter)set_payload,
      "UDP payload", NULL},
   {NULL},  /* Sentinel */
   };

static PyMethodDef udp_methods[] = {
   {NULL}  /* Sentinel */
   };

PyTypeObject UdpType = {
   PV_PyObject_HEAD_INIT
   "UdpObject",                  /*tp_name*/
   sizeof(DataObject),          /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)udp_dealloc,      /*tp_dealloc*/
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
   "PythonLibtrace UDP",         /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   udp_methods,                  /* tp_methods */
   0,                           /* tp_members */
   UDP_getseters,                /* tp_getset */
   &InternetType,               /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */ 
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)udp_init,           /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)udp_new,             /* tp_new */
   };


void initudp(void) {
   if (PyType_Ready(&UdpType) < 0) return;

   Py_TYPE(&UdpType) = &PyType_Type;

   Py_INCREF(&UdpType);
   PyModule_AddObject(plt_module, "udp", (PyObject *)&UdpType);
   }
