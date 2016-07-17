/* 1452, Fri 14 Mar 14 (PDT)
   1834, Mon 28 Oct 13 (NZDT)

   ip.c: RubyLibtrace, python version!

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

static void ip_dealloc(PyObject *self) {
   self->ob_type->tp_free((PyObject *)self);
   }

static PyObject *ip_new(PyTypeObject *type, PyObject *args) {
   DataObject *arg=NULL;  void *data, *l3p;  int rem;
   PyArg_ParseTuple(args, "O", (PyObject *)&arg);
   if (PyObject_IsInstance((PyObject *)arg, (PyObject *)&DataType)) {
      data = arg->data;  l3p = arg->l3p;  rem = arg->rem;
      if (((uint8_t *)l3p)[0] >> 4 != 4) {  /* Not IPv4 */
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
   DataObject *ip_obj = plt_new_object(&IpType,
      RLT_TYPE_IP, RLT_KIND_CPY, data, (PyObject *)arg,
      NULL, 0, 0, 0x0800, 0, l3p, rem, 0,  l3p, rem);
   // pltData_dump(ip_obj, "*leaving plt.ip()");  //debug
   return (PyObject *)ip_obj;
   }

static int ip_init(DataObject *self, PyObject *args) {
   return 0;
   }

static libtrace_ip_t *check_ip(DataObject *op, int x4) {
   /* Check we have a layer3 pointer, with at least x4 bytes remaining */
   if (!op->l3p) return NULL;
   libtrace_ip_t *lip = op->l3p;
   if (op->l3_rem < x4) return NULL;
   return lip;
   }

static PyObject *get_ident(DataObject *self, void *closure) {
   libtrace_ip_t *lip = check_ip(self, 6);
   if (!lip) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for ident");  return NULL;
      }
   return PV_PyInt_FromLong((long)ntohs(lip->ip_id));
   }
set_read_only(ident);

static PyObject *get_has_rf(DataObject *self, void *closure) {
   libtrace_ip_t *lip = check_ip(self, 7);
   if (!lip) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for has_rf");  return NULL;
      }
   uint8_t *nofp = (uint8_t *)lip;
   PyObject *result = (nofp[6] & 0x80) != 0 ? Py_True : Py_False;
   Py_INCREF(result);  return result; 
   }
set_read_only(has_rf);

static PyObject *get_has_df(DataObject *self, void *closure) {
   libtrace_ip_t *lip = check_ip(self, 7);
   if (!lip) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for has_df");  return NULL;
      }
   uint8_t *nofp = (uint8_t *)lip;
   PyObject *result = (nofp[6] & 0x40) != 0 ? Py_True : Py_False;
   Py_INCREF(result);  return result; 
   }
set_read_only(has_df);

static PyObject *get_has_mf(DataObject *self, void *closure) {
   libtrace_ip_t *lip = check_ip(self, 7);
   if (!lip) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for has_mf");  return NULL;
      }
   uint8_t *nofp = (uint8_t *)lip;
   PyObject *result = (nofp[6] & 0x20) != 0 ? Py_True : Py_False;
   Py_INCREF(result);  return result; 
   }
set_read_only(has_mf);

static PyObject *get_frag_offset(DataObject *self, void *closure) {
   libtrace_ip_t *lip = check_ip(self, 8);
   if (!lip) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for frag_offset");  return NULL;
      }
   uint16_t *nofp = (uint16_t *)lip;
   return PV_PyInt_FromLong((long)ntohs(nofp[3]) & 0x1FFF);
   }
set_read_only(frag_offset);

static PyObject *get_hdr_checksum(DataObject *self, void *closure) {
   libtrace_ip_t *lip = check_ip(self, 12);
   if (!lip) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for hdr_checksum");  return NULL;
      }
   return PV_PyInt_FromLong((long)ntohs(lip->ip_sum));
   }
static int set_hdr_checksum(DataObject *self,
      PyObject *value, void *closure) {
   if (self->kind != RLT_KIND_PKT) {
      PyErr_SetString(PyExc_ValueError,
         "Object didn't come from a plt Packet");  return -1;
      }
   libtrace_ip_t *lip = check_ip(self, 12); 
   if (!lip) {
       PyErr_SetString(PyExc_ValueError,
         "Data too short for icmp checksum");
      return -1;
      }
   if (!PV_PyInt_Check(value)) {
      PyErr_SetString(PyExc_TypeError,
         "Expected an integer");  return -1;
      }
   long cks_v = PV_PyInt_AsLong(value);
   if (cks_v < 0 || cks_v > 0xFFFF) {
      PyErr_SetString(PyExc_ValueError,
         "Checksum not 16-bit unsigned integer");  return -1;
      }
   lip->ip_sum = ntohs((uint16_t )cks_v);
   return 0;
   }

static PyObject *ip_checksum_ok(DataObject *self) {
   if (self->kind != RLT_KIND_PKT) {
      PyErr_SetString(PyExc_ValueError,
         "Object didn't come from a plt Packet");  return NULL;
      }
   libtrace_ip_t *lip = check_ip(self, 1); 
   if (lip)  /* Can get header length */
      lip = check_ip(self, 4*lip->ip_hl);  /* Header length */
   if (!lip) {  /* Too few bytes to compute checksum */
      PyObject *result = Py_None;  Py_INCREF(result);  return result;
      PyErr_SetString(PyExc_ValueError,
         "Data too short to compute ip checksum");
      return NULL;
      }
   uint16_t save_cks = lip->ip_sum;  lip->ip_sum = 0;
   uint16_t plt_cks = ~checksum(lip, lip->ip_hl*4);
   lip->ip_sum = save_cks;
   PyObject *result = plt_cks == save_cks ? Py_True : Py_False;
   Py_INCREF(result);  return result;
   }

static PyObject *ip_set_checksum(DataObject *self) {
   if (self->kind != RLT_KIND_PKT) {
      PyErr_SetString(PyExc_ValueError,
         "Object didn't come from a plt Packet");  return NULL;
      }
   libtrace_ip_t *lip = check_ip(self, 1); 
   if (lip)  /* Can get header length */
      lip = check_ip(self, 4*lip->ip_hl);  /* Header length */
   if (!lip) {  /* Too few bytes to compute checksum */
      PyObject *result = Py_None;  Py_INCREF(result);  return result;
      }
   lip->ip_sum = 0;
   lip->ip_sum = ~checksum(lip, lip->ip_hl*4);
   PyObject *result = Py_None;  Py_INCREF(result);  return result;
   }

static PyObject *get_payload(DataObject *self, void *closure) {
   libtrace_ip_t *lip = (libtrace_ip_t *)self->l3p;
   uint8_t proto;  uint32_t remaining = self->l3_rem;
   uint8_t *dp = trace_get_payload_from_ip(lip, &proto, &remaining);
   if (!dp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for IP payload");  return NULL;
      }
   PyObject *result;  /* Zero-length byte array is OK */
   result = PyByteArray_FromStringAndSize((char *)dp, remaining);
   if (result == NULL) return NULL;
   return result;
   }
set_read_only(payload);

static PyGetSetDef IP_getseters[] = {
   {"ident",
      (getter)get_ident, (setter)set_ident,
      "IP packet ID", NULL},
   {"has_rf",
      (getter)get_has_rf, (setter)set_has_rf,
      "IP Reserved flag", NULL},
   {"has_df",
      (getter)get_has_df, (setter)set_has_df,
      "IP Don't Fragment flag", NULL},
   {"has_mf",
      (getter)get_has_mf, (setter)set_has_mf,
      "IP More Fragments flag", NULL},
   {"frag_offset",
      (getter)get_frag_offset, (setter)set_frag_offset,
      "IP fragment offset", NULL},
   {"checksum",
      (getter)get_hdr_checksum, (setter)set_hdr_checksum,
      "IP header checksum", NULL},
   {"payload",
      (getter)get_payload, (setter)set_payload,
      "IP payload", NULL},
   {NULL},  /* Sentinel */
   };

static PyMethodDef ip_methods[] = {
   {"checksum_ok", (PyCFunction)ip_checksum_ok, METH_NOARGS,
      "Test whether ip checksum is correct" },
   {"set_checksum", (PyCFunction)ip_set_checksum, METH_NOARGS,
      "Set ip checksum to it's correct value" },
   {NULL}  /* Sentinel */
   };

PyTypeObject IpType = {
   PV_PyObject_HEAD_INIT
   "IpObject",                  /*tp_name*/
   sizeof(DataObject),          /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)ip_dealloc,      /*tp_dealloc*/
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
   "PythonLibtrace IP",         /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   ip_methods,                  /* tp_methods */
   0,                           /* tp_members */
   IP_getseters,                /* tp_getset */
   &InternetType,               /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */ 
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)ip_init,           /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)ip_new,             /* tp_new */
   };


void initip(void) {
   if (PyType_Ready(&IpType) < 0) return;

   Py_TYPE(&IpType) = &PyType_Type;

   Py_INCREF(&IpType);
   PyModule_AddObject(plt_module, "ip", (PyObject *)&IpType);
   }
