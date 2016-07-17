/* 1452, Fri 14 Mar 14 (PDT)
   1421, Fri  2 Aug 13 (CEST)

   trace.c: RubyLibtrace, python version!

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

// http://starship.python.net/crew/arcege/extwriting/pyext.html

PyTypeObject TraceType;

static void pltTrace_dealloc(TraceObject *self) {
   if (self->started) trace_destroy(self->tr);
   trace_destroy_packet(self->lt_pkt);
   Py_XDECREF(self->py_packet);
   PV_free_self;
   }

static PyObject *pltTrace_new(PyTypeObject *type, PyObject *args) {
   TraceObject *self = (TraceObject *)type->tp_alloc(type, 0);
   self->lt_pkt = trace_create_packet();
   self->py_packet = (DataObject *)(DataType.tp_alloc(&DataType, 0));
   return (PyObject *)self;
   }

static int pltTrace_init(TraceObject *self, PyObject *args) {
   int ulen = -1;  char *uri = NULL;
   if (!PyArg_ParseTuple(args, "s#:Trace_init", &uri, &ulen)) {
      PyErr_SetString(PyExc_ValueError, "Expected a string for URI");
      return -1;
      }
   libtrace_t *tr = trace_create(uri);
      /* libtrace doesn't check the URI until you start() it! */
   self->tr = tr;  self->started = 0;
   return 0;
   }

static PyObject *trace_conf_filter(TraceObject *self, PyObject *args) {
   FilterObject *p_flt = NULL;
   if (!PyArg_ParseTuple(args, "O:Trace_conf_filter", &p_flt)) {
      PyErr_SetString(PyExc_ValueError, "Expected a string for filter bpf");
      return NULL;
      }
   if (!PyObject_IsInstance((PyObject *)p_flt, (PyObject *)&FilterType)) {
      PyErr_SetString(PyExc_SystemError, "Expected a Filter object");
      return NULL;
      }
   if (trace_config(self->tr, TRACE_OPTION_FILTER, p_flt->flt) != 0) {
      PyErr_SetString(plt_exc_libtrace, "Failed to set filter");
      return NULL;
      }
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }

static PyObject *trace_conf_snaplen(TraceObject *self, PyObject *args) {
   int snaplen;
   if (!PyArg_ParseTuple(args, "i:Trace_conf_snaplen_init", &snaplen))
      return NULL;
   if (trace_config(self->tr, TRACE_OPTION_SNAPLEN, &snaplen) != 0) {
      set_err_msg("Failed to set snaplen = %d", snaplen);
      PyErr_SetString(plt_exc_libtrace, plt_err_msg);
      return NULL;
      }
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }

static PyObject *trace_conf_promisc(TraceObject *self, PyObject *args) {
   PyObject *p_promisc = NULL;
   int value;
   if (!PyArg_ParseTuple(args, "O:Trace_conf_snaplen", &p_promisc))
      return 0;
   if (p_promisc == Py_True) value = 1;
   else if (p_promisc == Py_False) value = 0;
   else {
      PyErr_SetString(PyExc_ValueError,
         "promisc value not true or false");
      return NULL;
      }
   if (trace_config(self->tr, TRACE_OPTION_PROMISC, &value)) {
      set_err_msg("Failed to set promisc = %s",
         value ? "true" : "false");
      PyErr_SetString(plt_exc_libtrace, plt_err_msg);
      return NULL;
      }
   if (trace_is_err(self->tr)) {
      libtrace_err_t lte = trace_get_err(self->tr);
      PyErr_SetString(plt_exc_libtrace, lte.problem);
      return NULL;
      }
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }

static PyObject *trace_plt_start(TraceObject *self) {
   if (trace_start(self->tr)) {
      libtrace_err_t lte = trace_get_err(self->tr);
      set_err_msg("Couldn't start trace: %s", lte.problem);
      PyErr_SetString(plt_exc_libtrace, plt_err_msg);
      return NULL;
      }
   else self->started = 1;
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }

static PyObject *trace_plt_pause(TraceObject *self) {
   if (!((TraceObject *)self)->started) {
      PyErr_SetString(plt_exc_libtrace, "Trace not started");
      return NULL;
      }
  if (trace_pause(self->tr)) {
      libtrace_err_t lte = trace_get_err(self->tr);
      set_err_msg("Couldn't pause trace: %s", lte.problem);
      PyErr_SetString(plt_exc_libtrace, plt_err_msg);
      return NULL;
      }
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }

static PyObject *trace_close(TraceObject *self) {
   if (self->started) {
      trace_destroy(self->tr);  self->started = 0;
      }
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }

static int get_packet(TraceObject *trace, DataObject *d) {
   uint16_t ethertype;  uint32_t l3_rem = 0;  int vlan = 0;
   if (!trace->started) {
      PyErr_SetString(plt_exc_libtrace, "Trace not started");
      return -1;
      }
   int r = trace_read_packet(trace->tr, trace->lt_pkt);
   if (r > 0) {
      libtrace_linktype_t linktype;  uint32_t l2_rem;  void *l3p;
      void *l2p = trace_get_layer2(trace->lt_pkt, &linktype, &l2_rem);
      if (!l2p) {
         PyErr_SetString(plt_exc_libtrace, "get layer2 failed");
         return -2;
         }
      else {
	 l3_rem = l2_rem;
         l3p = trace_get_payload_from_layer2(
            l2p, linktype, &ethertype, &l3_rem);
         if (!l3p) {
            PyErr_SetString(plt_exc_libtrace, "get layer2 payload failed");
            return -3;
	    }
	 if (ethertype == 0x8100) {  /* 802.1 Q VLAN tag */
            uint16_t vlan_et;  uint32_t vlan_rem;
	    uint16_t *vltp = (uint16_t *)l3p;  vlan = ntohs(vltp[0]);
            vlan_rem = l3_rem;
	    void *vlp = trace_get_payload_from_vlan(l3p, &vlan_et, &vlan_rem);
            if (!vlp) {
               PyErr_SetString(plt_exc_libtrace, "get vlan payload failed");
               return -4;
	       }
	    ethertype = vlan_et;
	    l2_rem -= vlp-l3p;  l3p = vlp;  l3_rem = vlan_rem;
	    }
         }
      d->type = RLT_TYPE_PKT;  d->kind = RLT_KIND_PKT;
      d->data = trace->lt_pkt;  d->mom = Py_None;
      d->l2p = l2p;  d->l2_rem = l2_rem;
      d->linktype = linktype;  d->ethertype = ethertype;  d->vlan_tag = vlan;
      d->l3p = l3p;  d->l3_rem = l3_rem;
      // pltData_dump(d, "*leaving get_packet()");  //debug
      return 1;  /* Successful read */
      }
   else if (r == 0)  /* End of trace */
      return 0;
   libtrace_err_t lte = trace_get_err(trace->tr);
   set_err_msg2("get packet failed: r=%d, %s", r, lte.problem);
   PyErr_SetString(plt_exc_libtrace, plt_err_msg);
   return -5;  /* trace_read_packet failed */
   }

static PyObject* trace_packet_iter(PyObject *self) {
   /* Called once to initialise an iteration */
   Py_INCREF(self);  return self;
   }

static PyObject *trace_packet_next(PyObject *self) {
   /* for pkt in trace (python)  replaces
      trace.each_packet { |pkt| ... } (ruby) */
   /* Called to get next result from iterator */
   TraceObject *t = (TraceObject *)self;
   int r = get_packet(t, t->py_packet);
   switch (r) {
   case 1: Py_INCREF(t->py_packet);  /* Read OK */
           return (PyObject *)t->py_packet;
   case 0: PyErr_SetNone(PyExc_StopIteration);  /* EOF */
           return NULL;  /* Raise StopIteration */
  default: return NULL;  /* Error, raise exception */
      }
   }

static PyObject *trace_read(TraceObject *self, PyObject *args) {
   DataObject *arg = NULL;
   if (!PyArg_ParseTuple(args, "O:trace_read", &arg))
      return NULL; 
   if (!(PyObject_IsInstance((PyObject *)arg, (PyObject *)&DataType)
	  && arg->type == RLT_TYPE_PKT)) {
      PyErr_SetString(PyExc_ValueError, "Expected a Packet object");
      return NULL;
      }
   int r = get_packet(self, arg);  /* Read into the Packet we were given */
      /* This is a borrowed reference, don't need to INCREF */
   PyObject *result;
   switch (r) {
   case 1: result = Py_True;  /* Read OK */
           break;
   case 0: result = Py_False;  /* EOF */
           break;
  default: return NULL;  /* Error, raise exception */
      }
   Py_INCREF(result);  return result;
   }

static PyObject *trace_packet_drops(TraceObject *self) {
   uint64_t drops = trace_get_dropped_packets(self->tr);
   return PyLong_FromUnsignedLongLong(drops);
   }

static PyObject *trace_accepted_packets(TraceObject *self) {
   uint64_t accepted = trace_get_accepted_packets(self->tr);
   return PyLong_FromUnsignedLongLong(accepted);
   }

static PyMethodDef Trace_methods[] = {
   {"conf_filter", (PyCFunction)trace_conf_filter, METH_VARARGS,
    "Set Trace Filter"},
   {"conf_snaplen", (PyCFunction)trace_conf_snaplen, METH_VARARGS,
    "Set Trace snaplen"},
   {"conf_promisc", (PyCFunction)trace_conf_promisc, METH_VARARGS,
    "Set Trace promisc"},
   {"start", (PyCFunction)trace_plt_start, METH_NOARGS,
    "Start Trace"},
   {"pause", (PyCFunction)trace_plt_pause, METH_NOARGS,
    "Pause Trace"},
   {"close", (PyCFunction)trace_close, METH_NOARGS,
    "Close Trace"},
   {"read_packet", (PyCFunction)trace_read, METH_VARARGS,
    "Read packet from Trace"},
   {"pkt_drops", (PyCFunction)trace_packet_drops, METH_NOARGS,
    "Trace packet drops"},
   {"pkt_accepts", (PyCFunction)trace_accepted_packets, METH_NOARGS,
    "Trace accepted packets"},
   {NULL}  /* Sentinel */
   };

PyTypeObject TraceType = {
   PV_PyObject_HEAD_INIT
   "TraceObject.support",     /*tp_name*/
   sizeof(TraceObject),       /*tp_basicsize*/
   0,                         /*tp_itemsize*/
   (destructor)pltTrace_dealloc,  /*tp_dealloc*/
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
   //   (reprfunc)plt_str,    /*tp_str*/
   0,                         /*tp_getattro*/
   0,                         /*tp_setattro (setattr works, this doesn't) */  
   0,                         /*tp_as_buffer*/
   Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
   "Python-libtrace Trace",    /* tp_doc */
   0,		               /* tp_traverse */
   0,		               /* tp_clear */
   0,                          /* tp_richcompare */
   //   (richcmpfunc)pltTrace_richcompare,  /* tp_richcompare */
   0,		               /* tp_weaklistoffset */
   trace_packet_iter,	       /* tp_iter */
   trace_packet_next,	       /* tp_iternext */
   Trace_methods,              /* tp_methods */
   0,                          /* tp_members */
   0,                          /* tp_getset */
   0,                          /* tp_base */
   0,                          /* tp_dict */
   0,                          /* tp_descr_get */ 
   0,                          /* tp_descr_set */
   0,                          /* tp_dictoffset */
   (initproc)pltTrace_init,    /* tp_init */
   0,                          /* tp_alloc */
   (newfunc)pltTrace_new,      /* tp_new */
   };


void inittrace(void) {
   if (PyType_Ready(&TraceType) < 0) return;

   Py_TYPE(&TraceType) = &PyType_Type;

   Py_INCREF(&TraceType);
   PyModule_AddObject(plt_module, "trace", (PyObject *)&TraceType);
   }
