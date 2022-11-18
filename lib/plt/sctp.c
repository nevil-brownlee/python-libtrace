/* 1428, Sat 27 Jub 2018 (NZDT)

   sctp.c: RubyLibtrace, python version!

   RFC 4960: Stream Control Transmission Protocol

   python-libtrace: a Python module to make it easy to use libtrace
   Copyright (C) 2018 by Nevil Brownlee, U Auckland | WAND

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

/* sctp class */

static void sctp_dealloc(PyObject *self) {
   self->ob_type->tp_free((PyObject *)self);
   }

static PyObject *sctp_new(PyTypeObject *type, PyObject *args) {
   DataObject *arg=NULL;  void *data, *l3p, *l4p = NULL;
   uint32_t l3_rem, rem;  uint8_t proto;  int ethertype;
   PyArg_ParseTuple(args, "O", (PyObject *)&arg);
   if (PyObject_IsInstance((PyObject *)arg, (PyObject *)&DataType)) {
      data = arg->data;  l3p = arg->l3p;  l3_rem = arg->l3_rem;
      if (arg->type < RLT_TYPE_Internet || arg->type >= RLT_TYPE_L4) {
         PyObject *result = Py_None;  Py_INCREF(result);  return result;
         }
      else {  /* DataObject is a Layer 4 object */
	 l3p = arg->l3p;  l3_rem = rem = arg->rem;
         if (arg->ethertype == 0x0800)
            l4p = trace_get_payload_from_ip(
               (libtrace_ip_t *)l3p, &proto, &rem);
         else if (arg->ethertype == 0x86DD)
            l4p = trace_get_payload_from_ip6(
               (libtrace_ip6_t *)l3p, &proto, &rem);
         if (l4p && proto != 132) {  /* Not SCTP transport */
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
      RLT_TYPE_SCTP, RLT_KIND_CPY, data, (PyObject *)arg,
      NULL, 0, 0, ethertype, 0,  l3p, l3_rem, 6,  l4p, rem);
   // pltData_dump(tcp_obj, "*leaving sctp.tcp()");  //debug
   return (PyObject *)tcp_obj;
   }

static int sctp_init(DataObject *self, PyObject *args) {
   return 0;
   }

static plt_sctp_t *get_sctp(DataObject *op, int x) {
   if (op->proto != 132) {
      PyErr_SetString(PyExc_ValueError, "Expected an SCTP object");
         return NULL;
      }
   if (op->rem < x) return NULL;
   plt_sctp_t *lsctp = op->dp;
   return lsctp;
   }

static PyObject *get_src_port(DataObject *self, void *closure) {
   plt_sctp_t *lsctp = get_sctp(self, 2);
   if (!lsctp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for src_port");  return NULL;
      }
   return PV_PyInt_FromLong((long)ntohs(*(uint16_t *)lsctp));
   }
set_read_only(src_port);

static PyObject *get_dst_port(DataObject *self, void *closure) {
   plt_sctp_t *lsctp = get_sctp(self, 4);
   if (!lsctp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for dst_port");  return NULL;
      }
   return PV_PyInt_FromLong((long)ntohs(*(uint16_t *)&lsctp[2]));
   }
set_read_only(dst_port);

static PyObject *get_verification_tag(DataObject *self, void *closure) {
   plt_sctp_t *lsctp = get_sctp(self, 8);
   if (!lsctp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for verification_tag");  return NULL;
      }
   return PyLong_FromUnsignedLong((unsigned long)ntohl(*(uint32_t *)&lsctp[4]));
   }
set_read_only(verification_tag);

static PyObject *get_checksum(DataObject *self, void *closure) {
   plt_sctp_t *lsctp = get_sctp(self, 12);
   if (!lsctp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for checksum");  return NULL;
      }
   return PyLong_FromUnsignedLong((unsigned long)ntohl(*(uint32_t *)&lsctp[8]));
   }
set_read_only(checksum);

PyTypeObject SctpChunkType;  /* Forward declaration fot Type object */

static PyObject *sctp_get_chunks(DataObject *self, void *closure) {
   plt_sctp_t *cp = get_sctp(self, 16);
   if (!cp) {
      PyErr_SetString(PyExc_ValueError,
         "Captured packet has no sctp chunks");  return NULL;
      }
   plt_sctp_t *fcp = &cp[12];  cp = fcp;
   int rem = self->rem-12,  /* Bytes left to examine */
      n_chunks = 0, clen;
   while (1) {
      if (rem < 4) {
         PyErr_SetString(PyExc_ValueError,
            "SCTP less than 4 bytes in chunk");  return NULL;
         }
      clen = ntohs(*(uint16_t *)&cp[2]);
      n_chunks += 1;  /* Count this chunk */
      rem -= clen;
      if (rem <= 0) {  /* May have been truncated on capture */
         break;
         }
      cp = &cp[clen];  /* Next chunk */
      }
   PyObject *clist = PyList_New(n_chunks);
   if (!clist) {
      PyErr_SetString(PyExc_ValueError,
         "Failed to create list for cunks");  return NULL;
      }
   rem = self->rem-12;  cp = fcp;  /* First chunk */
   int nc, lr;  for (nc = 0; nc != n_chunks; nc += 1) {
      int clen = ntohs(*(uint16_t *)&cp[2]);
      SctpChunkObject *chunk =
         (SctpChunkObject *)SctpChunkType.tp_alloc(&SctpChunkType, 0);
      chunk->sctp = self;  Py_INCREF(self);
      chunk->chunkp = cp;
      chunk->actual_length = clen;
      lr = PyList_SetItem(clist, nc, (PyObject *)chunk);
      if (lr) {
	 PyErr_SetString(PyExc_ValueError,
            "Failed to set chunk list item");  return NULL;
      }
      rem -= clen;  cp = &cp[clen];
      }
   return clist;
   }
set_read_only(chunks);

static PyGetSetDef SCTP_getseters[] = {
   {"src_port",
      (getter)get_src_port, (setter)set_src_port,
      "SCTP source port", NULL},
   {"dst_port",
      (getter)get_dst_port, (setter)set_dst_port,
      "SCTP dest port", NULL},
   {"verification_tag",
      (getter)get_verification_tag, (setter)set_verification_tag,
      "SCTP verification tag", NULL},
   {"checksum",
      (getter)get_checksum, (setter)set_checksum,
      "SCTP checksum", NULL},
   {"chunks",
      (getter)sctp_get_chunks, (setter)set_chunks,
      "SCTP chunks", NULL},
   {NULL},  /* Sentinel */
   };

static PyMethodDef sctp_methods[] = {
   {NULL}  /* Sentinel */
   };

PyTypeObject SctpType = {
   PV_PyObject_HEAD_INIT
   "SctpObject",                  /*tp_name*/
   sizeof(DataObject),          /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)sctp_dealloc,      /*tp_dealloc*/
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
   "PythonLibtrace SCTP",         /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   sctp_methods,                  /* tp_methods */
   0,                           /* tp_members */
   SCTP_getseters,                /* tp_getset */
   &InternetType,               /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */ 
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)sctp_init,           /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)sctp_new,             /* tp_new */
   };


/* Chunk class */

static void chunk_dealloc(SctpChunkObject *self) {
   Py_DECREF(self->sctp);
   PV_free_self;
   }

static PyObject *chunk_new(PyTypeObject *type) {
   PyObject *self = (PyObject *)type->tp_alloc(type, 0);
   return (PyObject *)self;
   } 

static int chunk_init(PyObject *self) {
   printf("chunk_init(): self=%p\n", self);  fflush(stdout);
   return 0;
   }

static sctp_chunk_t *get_chunk(SctpChunkObject *op, int x) {
   if (op->actual_length < x) return NULL;
   sctp_chunk_t *cp = op->chunkp;
   return cp;
   }

static PyObject *get_chunk_type(SctpChunkObject *self, void *closure) {
    sctp_chunk_t *chunk = get_chunk(self, 1);
    if (!chunk) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for chunk type");  return NULL;
      }
    return PV_PyInt_FromLong((long)*(uint8_t *)&chunk[0]);
   }
set_read_only(chunk_type);

static PyObject *get_chunk_flags(SctpChunkObject *self, void *closure) {
    sctp_chunk_t *chunk = get_chunk(self, 2);
    if (!chunk) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for chunk flags");  return NULL;
      }
   return PV_PyInt_FromLong((long)*(uint8_t *)&chunk[1]);
   }
set_read_only(chunk_flags);

static PyObject *get_chunk_length(SctpChunkObject *self, void *closure) {
    sctp_chunk_t *chunk = get_chunk(self, 4);
    if (!chunk) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for chunk length");  return NULL;
      }
    return PV_PyInt_FromLong((long)ntohs(*(uint16_t *)&chunk[2]));
   }
set_read_only(chunk_length);

static PyObject *get_chunk_is_ok(SctpChunkObject *self, void *closure) {
    sctp_chunk_t *chunk = get_chunk(self, 4);
    if (!chunk) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for chunk is_ok");  return NULL;
      }
   int ok = ntohs(*(uint16_t *)&chunk[2]) == self->actual_length;
   PyObject *result = ok ? Py_True : Py_False;
   Py_INCREF(result);  return result;
   }
set_read_only(chunk_is_ok);

static PyObject *get_chunk_bytes(SctpChunkObject *self, void *closure) {
    sctp_chunk_t *chunk = get_chunk(self, 4);
    if (!chunk) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for chunk");  return NULL;
      }
    PyObject *result = PyByteArray_FromStringAndSize(
       (char *)&self->chunkp[4], self->actual_length-4);
    if (result == NULL) return NULL;
    return result;
   }
set_read_only(chunk_bytes);

static PyGetSetDef chunk_getseters[] = {
   {"type",
      (getter)get_chunk_type, (setter)set_chunk_type,
      "SCTP Chunk type", NULL},
   {"flags",
      (getter)get_chunk_flags, (setter)set_chunk_flags,
      "SSCTP Chunk flags", NULL},
   {"length",
      (getter)get_chunk_length, (setter)set_chunk_length,
      "SCTP Chunk length", NULL},
   {"is_ok",
      (getter)get_chunk_is_ok, (setter)set_chunk_is_ok,
      "SCTP Chunk was captured in full", NULL},
   {"bytes",
      (getter)get_chunk_bytes, (setter)set_chunk_bytes,
      "SCTP Chunk payload bytes", NULL},
   {NULL},  /* Sentinel */
   };

static PyMethodDef chunk_methods[] = {   {NULL}  /* Sentinel */
   };

PyTypeObject SctpChunkType = {
   PV_PyObject_HEAD_INIT
   "SctpChunkObject",           /*tp_name*/
   sizeof(SctpChunkObject),       /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)chunk_dealloc,    /*tp_dealloc*/
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
   "PythonLibtrace SCTP Chunk",       /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   chunk_methods,                /* tp_methods */
   0,  /* None python-accessible*/  /* tp_members */
   chunk_getseters,              /* tp_getset */
   &SctpType,                   /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */ 
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)chunk_init,         /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)chunk_new,           /* tp_new */
   };


void initsctp(void) {
   if (PyType_Ready(&SctpType) <= 0) {
      Py_SET_TYPE(&SctpType, &PyType_Type);
      Py_INCREF(&SctpType);
      PyModule_AddObject(plt_module, "sctp", (PyObject *)&SctpType);
      }
   if (PyType_Ready(&SctpChunkType) <= 0) {
      Py_SET_TYPE(&SctpChunkType, &PyType_Type);
      Py_INCREF(&SctpChunkType);
      PyModule_AddObject(plt_module, "chunk", (PyObject *)&SctpChunkType);
      }
   }
