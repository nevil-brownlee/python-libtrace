/* 1452, Fri 14 Mar 14 (PDT)
   1325, Thu  7 Nov 13 (PST)

   ip6.c: RubyLibtrace, python version!

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

static void ip6_dealloc(PyObject *self) {
   self->ob_type->tp_free((PyObject *)self);
   }

static PyObject *ip6_new(PyTypeObject *type, PyObject *args) {
   DataObject *arg=NULL;  void *data, *l3p;  int rem;
   PyArg_ParseTuple(args, "O", (PyObject *)&arg);
   if (PyObject_IsInstance((PyObject *)arg, (PyObject *)&DataType)) {
      data = arg->data;  l3p = arg->l3p;  rem = arg->rem;
      if (((uint8_t *)l3p)[0] >> 4 != 6) {  /* Not IPv6 */
         PyObject *result = Py_None;  Py_INCREF(result);  return result;
         }
      }
   else if (PyByteArray_CheckExact(arg)) {
      data = NULL;
      l3p = PyByteArray_AsString((PyObject *)arg);
      rem = (int)PyByteArray_Size((PyObject *)arg);
      }
   else {
      PyErr_SetString(PyExc_ValueError,
         "Not a Data, Packet or ByteArray object");  return NULL;
      }
   Py_INCREF(arg);
   DataObject *ip6_obj = plt_new_object(&Ip6Type,
      RLT_TYPE_IP6, RLT_KIND_CPY, data, (PyObject *)arg,
      NULL, 0, 0, 0x86DD, 0, l3p, rem, 0,  l3p, rem);
   // pltData_dump(ip6_obj, "*leaving plt.ip6()");  //debug
   return (PyObject *)ip6_obj;
   }

static int ip6_init(DataObject *self, PyObject *args) {
   return 0;
   }

static libtrace_ip6_t *get_ip6(DataObject *op, int x6) {
   if (!op->l3p) return NULL;
   libtrace_ip6_t *l6p = op->l3p;
   int l3p_len = op->l3_rem;
   if (l3p_len < x6) return NULL;
   return l6p;
   }

static PyObject *get_flow_label(DataObject *self, void *closure) {
   libtrace_ip6_t *l6p = get_ip6(self, 4);
   if (!l6p) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for flow_label");  return NULL;
      }
   uint32_t flow = ntohl(l6p->flow);
   return  PV_PyInt_FromLong((long)flow & 0x000FFFFF);
   }
set_read_only(flow_label);

static PyObject *get_payload_len(DataObject *self, void *closure) {
   libtrace_ip6_t *l6p = get_ip6(self, 7);
   if (!l6p) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for payload_len");  return NULL;
      }
   return PV_PyInt_FromLong((long)ntohs(l6p->plen));
   }
set_read_only(payload_len);

static PyObject *get_next_hdr(DataObject *self, void *closure) {
   libtrace_ip6_t *l6p = get_ip6(self, 7);
   if (!l6p) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for next_hdr");  return NULL;
      }
   return PV_PyInt_FromLong((long)l6p->nxt);
   }
set_read_only(next_hdr);

static PyObject *get_payload(DataObject *self, void *closure) {
   libtrace_ip6_t *lip6 = (libtrace_ip6_t *)self->l3p;
   uint8_t proto;  uint32_t remaining = self->l3_rem;
   uint8_t *dp = trace_get_payload_from_ip6(lip6, &proto, &remaining);
   if (!dp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for IPv6 payload");  return NULL;
      }
   PyObject *result;  /* Zero-length byte array is OK */
   result = PyByteArray_FromStringAndSize((char *)dp, remaining);
   if (result == NULL) return NULL;
   return result;
   }
set_read_only(payload);

static PyGetSetDef IP6_getseters[] = {
   {"flow_label",
      (getter)get_flow_label, (setter)set_flow_label,
      "IP packet ID", NULL},
   {"payload_len",
      (getter)get_payload_len, (setter)set_payload_len,
      "IP Reserved flag", NULL},
   {"next_hdr",
      (getter)get_next_hdr, (setter)set_next_hdr,
      "IP Don't Fragment flag", NULL},
   {"payload",
      (getter)get_payload, (setter)set_payload,
      "IP payload", NULL},
   {NULL},  /* Sentinel */
   };

static PyMethodDef ip6_methods[] = {
  //   {"version", (PyCFunction)ip6_version, METH_NOARGS,
  //    "Ip6 Version" },
   {NULL}  /* Sentinel */
   };

PyTypeObject Ip6Type = {
   PV_PyObject_HEAD_INIT
   "Ip6Object",                 /*tp_name*/
   sizeof(DataObject),          /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)ip6_dealloc,     /*tp_dealloc*/
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
   "PythonLibtrace IP6",        /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   ip6_methods,                 /* tp_methods */
   0,                           /* tp_members */
   IP6_getseters,               /* tp_getset */
   &InternetType,               /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */ 
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)ip6_init,          /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)ip6_new,            /* tp_new */
   };


void initip6(void) {
   if (PyType_Ready(&Ip6Type) < 0) return;

   Py_TYPE(&Ip6Type) = &PyType_Type;

   Py_INCREF(&Ip6Type);
   PyModule_AddObject(plt_module, "ip6", (PyObject *)&Ip6Type);
   }
