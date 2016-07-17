/* 1452, Fri 14 Mar 14 (PDT)
   1214, Sun 24 Nov 13 (NZDT)

   outputtrace.c: RubyLibtrace, python version!

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

#include <fcntl.h>  /* For file creation flags */

PyTypeObject OutputTraceType;

static void pltOutputTrace_dealloc(OutputTraceObject *self) {
   if (self->started) trace_destroy_output(self->op);
   PV_free_self;
   }

static PyObject *pltOutputTrace_new(PyTypeObject *type, PyObject *args) {
   OutputTraceObject *self = (OutputTraceObject *)type->tp_alloc(type, 0);
   return (PyObject *)self;
   }

static int pltOutputTrace_init(OutputTraceObject *self, PyObject *args) {
   int ulen = -1;  char *uri = NULL;
   if (!PyArg_ParseTuple(args, "s#:OutputTrace_init", &uri, &ulen)) {
      PyErr_SetString(PyExc_ValueError, "Expected a string for URI");
      return -1;
      }
   libtrace_out_t *tr = trace_create_output(uri);
   if (trace_is_err_output(tr)) {
      libtrace_err_t lte = trace_get_err_output(tr);
      set_err_msg("Couldn't create outputTrace: %s", lte.problem);
      PyErr_SetString(PyExc_ValueError, plt_err_msg);
      return -1;
      }
   self->op = tr;  self->started = 0;
   return 0;
   }

#if 0  /* libtrace trace_option_output_t doesn't allow OPTION_SNAPLEN */
static PyObject *output_conf_snaplen(OutputTraceObject *self, PyObject *args) {
   int snaplen;
   if (!PyArg_ParseTuple(args, "i:Trace_conf_snaplen_init", &snaplen))
      return NULL;
   if (trace_config_output(self->op, TRACE_OPTION_SNAPLEN, &snaplen) != 0) {
      set_err_msg("Failed to set snaplen = %d", snaplen);
      PyErr_SetString(plt_exc_libtrace, plt_err_msg);
      return NULL;
      }
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }
#endif

static PyObject *output_conf_fileflags(OutputTraceObject *self, PyObject *args) {
   int flags = -1;
   if (!PyArg_ParseTuple(args, "i:OutputTrace_conf_file_flags", &flags)) {
      PyErr_SetString(PyExc_ValueError, "Expected an integer");
      return NULL;
      }
   if (trace_config_output(self->op, TRACE_OPTION_OUTPUT_FILEFLAGS, &flags) != 0) {
      set_err_msg("Failed to set output file flags = %d", flags);
      PyErr_SetString(plt_exc_libtrace, plt_err_msg);
      return NULL;
      }
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }

static PyObject *output_conf_compress_type(OutputTraceObject *self, PyObject *args) {
   int type = -1;
   if (!PyArg_ParseTuple(args, "i:OutputTrace_compress_type", &type)) {
      PyErr_SetString(PyExc_ValueError, "Expected an integer");
      return NULL;
      }
   if (type < 0 || type > 9) {
      PyErr_SetString(PyExc_ValueError, "compress_type value must be 0 to 9");
      return NULL;
      }
   if (trace_config_output(self->op,
         TRACE_OPTION_OUTPUT_COMPRESSTYPE, &type) != 0) {
      libtrace_err_t lte = trace_get_err_output(self->op);
      set_err_msg("Couldn't set OutputTrace compress_type: %s", lte.problem);
      PyErr_SetString(plt_exc_libtrace, plt_err_msg);
      return NULL;
      }
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }

static PyObject *output_conf_compress_level(OutputTraceObject *self, PyObject *args) {
   int level;
   if (!PyArg_ParseTuple(args, "i:OutputTrace_compress_level", &level)) {
      PyErr_SetString(PyExc_ValueError, "Expected an integer");
      return NULL;
      }
   if (trace_config_output(self->op, TRACE_OPTION_OUTPUT_COMPRESS, &level) != 0) {
      libtrace_err_t lte = trace_get_err_output(self->op);
      set_err_msg("Couldn't set OutputTrace compress_type: %s", lte.problem);
      PyErr_SetString(plt_exc_libtrace, plt_err_msg);
      return NULL;
      }
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }

static PyObject *outputTrace_plt_start(OutputTraceObject *self) {
   if (trace_start_output(self->op)) {
      libtrace_err_t lte = trace_get_err_output(self->op);
      set_err_msg("Couldn't start OutputTrace: %s", lte.problem);
      PyErr_SetString(plt_exc_libtrace, plt_err_msg);
      return NULL;
      }
   else self->started = 1;
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }

static PyObject *outputTrace_close(OutputTraceObject *self) {
   if (self->started) {
      trace_destroy_output(self->op);  self->started = 0;
      }
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }

static PyObject *outputTrace_write(OutputTraceObject *self, PyObject *args) {
   DataObject *arg=NULL;
   PyArg_ParseTuple(args, "O", (PyObject *)&arg);
   if (!(PyObject_IsInstance((PyObject *)arg, (PyObject *)&DataType) &&
         arg->type == RLT_TYPE_PKT)) {
      PyErr_SetString(PyExc_ValueError, "Expected a Packet object");
      return NULL;
      }
   if (!self->started) {
      PyErr_SetString(plt_exc_libtrace, "OutputTrace not started");
      return NULL;
      }
   int r = trace_write_packet(self->op, arg->data);
   if (r <= 0) {
      libtrace_err_t lte = trace_get_err_output(self->op);
      set_err_msg("OutputTrace_write failed: %s", lte.problem);
      PyErr_SetString(plt_exc_libtrace, plt_err_msg);
      return NULL;
      }
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }

static PyMethodDef OutputTrace_methods[] = {
   {"conf_file_flags", (PyCFunction)output_conf_fileflags, METH_VARARGS,
    "Set output fileflags, e.g. O_APPEND"},
   //   {"conf_snaplen", (PyCFunction)output_conf_snaplen, METH_VARARGS,
   //    "Set output snaplen"},
   {"conf_compress_type", (PyCFunction)output_conf_compress_type, METH_VARARGS,
    "Set output compression type"},
   {"conf_compress_level", (PyCFunction)output_conf_compress_level,
      METH_VARARGS, "Set output compression level"},
   {"start_output", (PyCFunction)outputTrace_plt_start, METH_NOARGS,
    "Start output"},
   {"close_output", (PyCFunction)outputTrace_close, METH_NOARGS,
    "Close output"},
   {"write_packet", (PyCFunction)outputTrace_write, METH_VARARGS,
    "Write packet to OutputTrace"},
   {NULL}  /* Sentinel */
   };

PyTypeObject OutputTraceType = {
   PV_PyObject_HEAD_INIT
   "OutputTrace",             /*tp_name*/
   sizeof(OutputTraceObject),  /*tp_basicsize*/
   0,                         /*tp_itemsize*/
   (destructor)pltOutputTrace_dealloc,  /*tp_dealloc*/
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
   0,                         /*tp_str*/
   0,                         /*tp_getattro*/
   0,                         /*tp_setattro (setattr works, this doesn't) */  
   0,                         /*tp_as_buffer*/
   Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
   "Python-libtrace OutputTrace",    /* tp_doc */
   0,		               /* tp_traverse */
   0,		               /* tp_clear */
   0,                          /* tp_richcompare */
   0,		               /* tp_weaklistoffset */
   0,                          /* tp_iter */
   0,                          /* tp_iternext */
   OutputTrace_methods,        /* tp_methods */
   0,                          /* tp_members */
   0,                          /* tp_getset */
   0,                          /* tp_base */
   0,                          /* tp_dict */
   0,                          /* tp_descr_get */ 
   0,                          /* tp_descr_set */
   0,                          /* tp_dictoffset */
   (initproc)pltOutputTrace_init, /* tp_init */
   0,                          /* tp_alloc */
   (newfunc)pltOutputTrace_new,  /* tp_new */
   };


/* Filter class */

static void filter_dealloc(FilterObject *self) {
   if (self->used) trace_destroy_filter(self->flt);
   PV_free_self;
   }

static PyObject *filter_new(PyTypeObject *type, PyObject *args) {
   PyObject *self = (PyObject *)type->tp_alloc(type, 0);
   return self;
   }

static int filter_init(FilterObject *self, PyObject *args) {
   char *bpf = NULL;
   if (!PyArg_ParseTuple(args, "s:Filter_init", &bpf))
      return 0;
   libtrace_filter_t *f = trace_create_filter(bpf);
   self->flt = f;  self->used = 1;
   return 0;
   }

static PyGetSetDef Filter_getseters[] = {
   {NULL},  /* Sentinel */
   };

static PyMethodDef Filter_methods[] = {
   {NULL}  /* Sentinel */
   };

PyTypeObject FilterType = {
   PV_PyObject_HEAD_INIT
   "FilterObject",              /*tp_name*/
   sizeof(FilterObject),        /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)filter_dealloc,  /*tp_dealloc*/
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
   "PythonLibtrace Filter",     /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   Filter_methods,              /* tp_methods */
   0,                           /* tp_members */
   Filter_getseters,            /* tp_getset */
   0,                           /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */ 
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)filter_init,       /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)filter_new,         /* tp_new */
   };


void initoutputtrace(void) {
   if (PyType_Ready(&OutputTraceType) < 0) return;
   Py_TYPE(&OutputTraceType) = &PyType_Type;
   if (PyType_Ready(&FilterType) < 0) return;
   Py_TYPE(&FilterType) = &PyType_Type;

   PyModule_AddObject(plt_module, "O_APPEND",
      PyLong_FromLong(O_APPEND));

   PyModule_AddObject(plt_module, "NO_COMPRESSION",
      PyLong_FromLong(TRACE_OPTION_COMPRESSTYPE_NONE));
   PyModule_AddObject(plt_module, "ZLIB_COMPRESSION",
      PyLong_FromLong(TRACE_OPTION_COMPRESSTYPE_ZLIB));
   PyModule_AddObject(plt_module, "BZIP2_COMPRESSION",
      PyLong_FromLong(TRACE_OPTION_COMPRESSTYPE_BZ2));
   PyModule_AddObject(plt_module, "LZO_COMPRESSION",
      PyLong_FromLong(TRACE_OPTION_COMPRESSTYPE_LZO));

   Py_INCREF(&OutputTraceType);
   PyModule_AddObject(plt_module, "output_trace", (PyObject *)&OutputTraceType);
   Py_INCREF(&FilterType);
   PyModule_AddObject(plt_module, "filter", (PyObject *)&FilterType);
   }
