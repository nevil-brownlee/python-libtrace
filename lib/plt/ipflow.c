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
#include "../plt/plt.h"

typedef struct {  /* Python stuff starts here */
   PyObject_HEAD
   int version;  /* 4 or 6 */
   struct {
      int proto;
      uint16_t sport, dport;
      union {
	 struct {
            uint8_t saddr[16], daddr[16];
	    } v4;
	 struct {
            uint8_t saddr[16], daddr[16];
	    } v6;
         }
      } fkey;
   } IPflowObject;

static void IPflow_dealloc(PyObject *self) {
   self->ob_type->tp_free((PyObject *)self);
   }

static PyObject *IPflow_new(PyTypeObject *type, PyObject *args) {
   IPflowObject *self = (IPflowObject *)type->tp_alloc(type, 0);
   return (PyObject *)self;
   }

static int IPflow_init(IPflowObject *type, PyObject *args) {
   DataObject *dp = NULL;
   if (!PyArg_ParseTuple(args, "O:IPflow", &dp)) {
      PyErr_SetString(PyExc_ValueError, "Expected an object");
      return -1;
      }
   if (!PyObject_IsInstance((PyObject *)dp, (PyObject *)&PacketType)) {
      PyErr_SetString(PyExc_SystemError, "Expected a Data object");
      return -1;
      }
   if (dp->kind != RLT_KIND_PKT) {
      PyErr_SetString(PyExc_ValueError,
         "Object didn't come from a plt Packet");  return -1;
      }
   uint16_t ethertype;  uint32_t remaining = dp->l2_rem;
   void *l3p = trace_get_payload_from_layer2(
      dp->l2p, dp->linktype, &ethertype, &remaining);
   if (l3p) {
      uint8_t proto, *trans;
      trans = (uint8_t *)trace_get_transport(dp->data, &proto, &remaining);
      if (trans) {
 	 return 0;  /* Initialised OK */
         }
      }
   PyErr_SetString(PyExc_ValueError,
      "Couldn't get Layer3 data");
   return 0;
   }

static PyObject *IPflow_get_dummy(DataObject *self) {
   PyObject *result = PyInt_FromLong((long)0);
   if (result == NULL) return NULL;
   return result;
   }
set_read_only(dummy);

static PyGetSetDef Packet_getseters[] = {
   {"dummy",
      (getter)IPflow_get_dummy, (setter)set_dummy,
      "IPflow dummy", NULL},
   {NULL},  /* Sentinel */
   };

static PyObject *IPflow_reverse_key(DataObject *self) {
   PyObject *result = PyInt_FromLong((long)0);
   if (result == NULL) return NULL;
   return result;
   }

static PyMethodDef IPflow_methods[] = {
   {"reverse_key", (PyCFunction)IPflow_reverse_key, METH_VARARGS,
      "Swap source and destination files on an IPflow"},
   {NULL}  /* Sentinel */
   };

PyTypeObject IPflowType = {
   PyObject_HEAD_INIT(NULL)
   0,                         /*ob_size*/
   "IPflow",                 /*tp_name*/
   sizeof(DataObject),        /*tp_basicsize*/
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
   IPflow_methods,            /* tp_methods */
   0,                         /* tp_members */
   Packet_getseters,          /* tp_getset */
   &DataType,                 /* tp_base */
   0,                         /* tp_dict */
   0,                         /* tp_descr_get */ 
   0,                         /* tp_descr_set */
   0,                         /* tp_dictoffset */
   (initproc)IPflow_init,    /* tp_init */
   0,                        /* tp_alloc */
   (newfunc)IPflow_new,      /* tp_new */
   };

void initipflow(void)  {
   if (PyType_Ready(&IPflowType) < 0) return;
   Py_TYPE(&IPflowType) = &PyType_Type;

   Py_INCREF(&IPflowType);
   PyModule_AddObject(plt_module, "IPflow", (PyObject *)&IPflowType);
}
