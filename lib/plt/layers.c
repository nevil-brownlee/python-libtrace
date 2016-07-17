/* 1452, Fri 14 Mar 14 (PDT)
   1931, Sun  3 Nov 13 (PST)

   layers.c: RubyLibtrace, python version!

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

static void layer2_dealloc(PyObject *self) {
   self->ob_type->tp_free((PyObject *)self);
   }

static PyObject *layer2_new(PyTypeObject *type) {
   printf("pltLayer2_new() called ----\n");  fflush(stdout);
   PyObject *self = (PyObject *)type->tp_alloc(type, 0);
   return self;
   }

static int layer2_init(PyObject *self) {
   printf("pltLayer2_init() called ----\n");  fflush(stdout);
   return 0;
   }

static PyMethodDef layer2_methods[] = {
   {NULL}  /* Sentinel */
   };

PyTypeObject Layer2Type = {
   PV_PyObject_HEAD_INIT
   "Layer2Object",              /*tp_name*/
   sizeof(DataObject),          /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)layer2_dealloc,  /*tp_dealloc*/
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
   //   (reprfunc)plt_str,      /*tp_str*/
   0,                           /*tp_getattro*/
   0,                           /*tp_setattro (setattr works, this doesn't) */  
   0,                           /*tp_as_buffer*/
   Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
   "PythonLibtrace Layer2",    /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,	    	                /* tp_weaklistoffset */
   0,	  	                /* tp_iter */
   0,	  	                /* tp_iternext */
   layer2_methods,              /* tp_methods */
   0,                           /* tp_members */
   0,                           /* tp_getset */
   &DataType,                   /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */ 
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)layer2_init,       /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)layer2_new,         /* tp_new */
   };


static void layer3_dealloc(PyObject *self) {
   self->ob_type->tp_free((PyObject *)self);
   }

static PyObject *layer3_new(PyTypeObject *type) {
   printf("pltLayer3_new() called ----\n");  fflush(stdout);
   PyObject *self = (PyObject *)type->tp_alloc(type, 0);
   return self;
   }

static int layer3_init(PyObject *self) {
   printf("pltLayer3_init() called ----\n");  fflush(stdout);
   return 0;
   }

static PyMethodDef layer3_methods[] = {
   {NULL}  /* Sentinel */
   };

PyTypeObject Layer3Type = {
   PV_PyObject_HEAD_INIT
   "Layer3Object",              /*tp_name*/
   sizeof(DataObject),          /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)layer3_dealloc,  /*tp_dealloc*/
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
   //   (reprfunc)plt_str,      /*tp_str*/
   0,                           /*tp_getattro*/
   0,                           /*tp_setattro (setattr works, this doesn't) */  
   0,                           /*tp_as_buffer*/
   Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
   "PythonLibtrace Layer3",    /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,	    	                /* tp_weaklistoffset */
   0,	  	                /* tp_iter */
   0,	  	                /* tp_iternext */
   layer3_methods,              /* tp_methods */
   0,                           /* tp_members */
   0,                           /* tp_getset */
   &DataType,                   /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */ 
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)layer3_init,       /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)layer3_new,         /* tp_new */
   };


static void transport_dealloc(PyObject *self) {
   self->ob_type->tp_free((PyObject *)self);
   }

static PyObject *transport_new(PyTypeObject *type) {
   printf("pltTransport_new() called ----\n");  fflush(stdout);
   PyObject *self = (PyObject *)type->tp_alloc(type, 0);
   return self;
   }

static int transport_init(PyObject *self) {
   printf("pltTransport_init() called ----\n");  fflush(stdout);
   return 0;
   }

static PyGetSetDef Transport_getseters[] = {
   {NULL},  /* Sentinel */
   };

static PyMethodDef transport_methods[] = {
  //  {"set_checksums", (PyCFunction)set_checksums, METH_NOARGS,
  //    "Set Packet's IP and transport checksums"},
   {NULL}  /* Sentinel */
};

PyTypeObject TransportType = {
   PV_PyObject_HEAD_INIT
   "TransportObject",           /*tp_name*/
   sizeof(DataObject),          /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)transport_dealloc,  /*tp_dealloc*/
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
   //   (reprfunc)plt_str,      /*tp_str*/
   0,                           /*tp_getattro*/
   0,                           /*tp_setattro (setattr works, this doesn't) */  
   0,                           /*tp_as_buffer*/
   Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
   "PythonLibtrace Transport",    /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,	    	                /* tp_weaklistoffset */
   0,	  	                /* tp_iter */
   0,	  	                /* tp_iternext */
   transport_methods,           /* tp_methods */
   0,                           /* tp_members */
   Transport_getseters,         /* tp_getset */
   &Layer3Type,                 /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */ 
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)transport_init,    /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)transport_new,       /* tp_new */
};

void initlayers(void) {
   if (PyType_Ready(&Layer2Type) < 0) return;
   if (PyType_Ready(&Layer3Type) < 0) return;
   if (PyType_Ready(&TransportType) < 0) return;

   Py_TYPE(&Layer2Type) = &PyType_Type;
   Py_TYPE(&Layer3Type) = &PyType_Type;
   Py_TYPE(&TransportType) = &PyType_Type;

   PyModule_AddObject(plt_module, "TRACE_TYPE_ETH",
		      PyLong_FromLong(TRACE_TYPE_ETH));
   PyModule_AddObject(plt_module, "TRACE_TYPE_ATM",
		      PyLong_FromLong(TRACE_TYPE_ATM));
   PyModule_AddObject(plt_module, "TRACE_TYPE_80211",
		      PyLong_FromLong(TRACE_TYPE_80211));
   PyModule_AddObject(plt_module, "TRACE_TYPE_LINUX_SLL",
		      PyLong_FromLong(TRACE_TYPE_LINUX_SLL));
   PyModule_AddObject(plt_module, "TRACE_TYPE_PFLOG",
		      PyLong_FromLong(TRACE_TYPE_PFLOG));
   PyModule_AddObject(plt_module, "TRACE_TYPE_DUCK",
		      PyLong_FromLong(TRACE_TYPE_DUCK));
   PyModule_AddObject(plt_module, "TRACE_TYPE_80211_RADIO",
		      PyLong_FromLong(TRACE_TYPE_80211_RADIO));
   PyModule_AddObject(plt_module, "TRACE_TYPE_LLCSNAP",
		      PyLong_FromLong(TRACE_TYPE_LLCSNAP));
   PyModule_AddObject(plt_module, "TRACE_TYPE_PPP",
		      PyLong_FromLong(TRACE_TYPE_PPP));
   PyModule_AddObject(plt_module, "TRACE_TYPE_METADATA",
		      PyLong_FromLong(TRACE_TYPE_METADATA));
   PyModule_AddObject(plt_module, "TRACE_TYPE_NONDATA",
		      PyLong_FromLong(TRACE_TYPE_NONDATA));

   Py_INCREF(&Layer2Type);
   PyModule_AddObject(plt_module, "Layer2", (PyObject *)&Layer2Type);
   Py_INCREF(&Layer3Type);
   PyModule_AddObject(plt_module, "Layer3", (PyObject *)&Layer3Type);
   Py_INCREF(&TransportType);
   PyModule_AddObject(plt_module, "Transport", (PyObject *)&TransportType);
   }
