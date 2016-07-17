/* 1452, Fri 14 Mar 14 (PDT)
   0530, Tue 12 Nov 13 (AEDT)  United 863

   icmp.c: RubyLibtrace, python version!

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

/* ICMP layouts from RFC 792

Return IP object from byte 8 ...
 3  Dest unreachable
 4  Source quench
 5  Redirect (gateway address in icmp bytes 4-7) <<<
11  Time exceeded
12  Parameter problem

Return Da
ta object from byte 8 ...
Echo req,reply
 8,0 Ident in bytes 2-3, seq nbr in 4-5, Data follows from byte 8

13 timestamp          Originate/Receive/Transmit timestamps,   
14 timestamp reply      three 4-byte timestamps from byte 8
                        (ms since midnight), RFC 778

15 info request   same as timestamp
16 info reply

From RFC 1256  (not worth decoding these!)

 9 Router Advertisment  list of v4 addresses  
10 Router solicitation  No data fields  */

struct icmp {
   uint8_t type;             /* message type */
   uint8_t code;             /* type sub-code */
   uint16_t checksum;
   union {
      struct {               /* 8,0: Echo */
         uint16_t id;
         uint16_t sequence;
         } echo;
      struct {                /* 3: Destination Unreachable */
         uint32_t unused;
         libtrace_ip_t ip;    /* Hdr + first 64 bytes of original datagram */
         } unreachable;
      uint32_t un_gateway;    /* 5: Redirect, IPv4 gateway address */
      } un;
   };

static void icmp_dealloc(PyObject *self) {
   self->ob_type->tp_free((PyObject *)self);
   }

static PyObject *icmp_new(PyTypeObject *type, PyObject *args) {
   DataObject *arg=NULL;  uint32_t remaining;  uint8_t proto;
   uint8_t *l4p = NULL;
   PyArg_ParseTuple(args, "O", (PyObject *)&arg);
   if (PyObject_IsInstance((PyObject *)arg, (PyObject *)&DataType)) {
      if (arg->ethertype == 0x0800) {
 	 remaining = arg->l3_rem;
         l4p = trace_get_payload_from_ip(
            (libtrace_ip_t *)arg->l3p, &proto, &remaining);
         }
      if (l4p && proto == 1) {
         if (remaining >= 2) {  /* Need at least type and code */
	    Py_INCREF(arg);
    	    DataObject *icmp_obj = plt_new_object(&IcmpType,
	       RLT_TYPE_ICMP, RLT_KIND_CPY, arg->data, (PyObject *)arg,
	       arg->l2p, arg->l2_rem,
               arg->linktype, arg->ethertype, arg->vlan_tag,
               arg->l3p, arg->l3_rem, 1,  l4p, remaining);
            // pltData_dump(icmp_obj, "*leaving plt.icmp(Data)");  //debug
            return (PyObject *)icmp_obj;
	    }
         }
      else {  /* Not a Layer3 object */
         PyObject *result = Py_None;  Py_INCREF(result);  return result;
         }
      }
   else if (PyByteArray_CheckExact(arg)) {
      l4p = (uint8_t *)PyByteArray_AsString((PyObject *)arg);
      remaining = (uint32_t)PyByteArray_Size((PyObject *)arg);
      }
   else {
      PyErr_SetString(PyExc_ValueError,
         "Not a Data, Packet or ByteArray object");  return NULL;
      }
   Py_INCREF(arg);
   DataObject *icmp_obj = plt_new_object(&IcmpType,
      RLT_TYPE_ICMP, RLT_KIND_CPY, NULL, (PyObject *)arg,
      NULL, 0, 0, 0x0800, 0, NULL, 0, 1,  l4p, remaining);
   pltData_dump(icmp_obj, "*leaving plt.icmp(ByteArray)");  //debug
   return (PyObject *)icmp_obj;
   }

static int icmp_init(DataObject *self, PyObject *args) {
   return 0;
   }

static struct icmp *get_icmp(DataObject *op, int x) {
   /*  Python gets to objects vistheir PythonTypes, so we can
       use this for all the objects that use our icmp struct */
   if (op->rem < x) return NULL;
   struct icmp *icmp = op->dp;
   return icmp;
   }

static PyObject *get_type(DataObject *self, void *closure) {
    struct icmp *icmp = get_icmp(self, 1);
    if (!icmp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for type");  return NULL;
      }
   return PV_PyInt_FromLong((long)icmp->type);
   }
set_read_only(type);

static PyObject *get_code(DataObject *self, void *closure) {
    struct icmp *icmp = get_icmp(self, 2);
    if (!icmp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for code");  return NULL;
      }
   return PV_PyInt_FromLong((long)icmp->code);
   }
set_read_only(code);

static PyObject *get_checksum(DataObject *self, void *closure) {
    struct icmp *icmp = get_icmp(self, 4);
    if (!icmp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for checksum");  return NULL;
      }
   return PyLong_FromUnsignedLong((unsigned long)ntohs(icmp->checksum));
   }
static int set_checksum(DataObject *self,
      PyObject *value, void *closure) {
   if (self->kind != RLT_KIND_PKT) {
      PyErr_SetString(PyExc_ValueError,
         "Object didn't come from a plt Packet");  return -1;
      }
   struct icmp *icmp = get_icmp(self, 4); 
   if (!icmp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for icmp checksum");
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
   icmp->checksum = ntohs((uint16_t)cks_v);
   return 0;
   }

static PyObject *get_payload(DataObject *self, void *closure) {
    struct icmp *icmp = get_icmp(self, 12);
    if (!icmp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for payload");  return NULL;
      }
   PyTypeObject *py_type;  int rlt_type;
   switch (icmp->type) {
   case  3:  /* Dest unreachable */
   case  4:  /* Source quench */
   case  5:  /* Redirect (gateway address in icmp bytes 4-7) */
   case 11:  /* Time exceeded */
   case 12:  /* Parameter problem */
      py_type = &IpType;  rlt_type = RLT_TYPE_IP;
      break;
   default:
      py_type = &DataType;  rlt_type = RLT_TYPE_DATA;
      }
   Py_INCREF(self);
   DataObject *icmp_obj = plt_new_object(py_type,
      rlt_type, RLT_KIND_CPY, NULL, (PyObject *)self,
      self->l2p, self->l2_rem,
      self->linktype, self->ethertype, self->vlan_tag,
      self->l3p, self->l3_rem, 1,  self->dp+8, self->rem-8);
   // pltData_dump(icmp_obj, "*leaving icmp.get_payload(Data)");  //debug
   return (PyObject *)icmp_obj;
   }
set_read_only(payload);

static PyObject *get_echo(DataObject *self) {
   Py_INCREF(self);
   DataObject *echo_obj = plt_new_object(&EchoType,
      self->type, RLT_KIND_CPY, NULL, (PyObject *)self,
      self->l2p, self->l2_rem,
      self->linktype, self->ethertype, self->vlan_tag,
      self->l3p, self->l3_rem, self->proto,  self->dp, self->rem);
   // pltData_dump(echo_obj, "*leaving icmp.get_echo()");  //debug
   return (PyObject *)echo_obj;
   }
set_read_only(echo); 

static PyObject *get_redirect(DataObject *self) {
   Py_INCREF(self);
   DataObject *redirect_obj = plt_new_object(&RedirectType,
      self->type, RLT_KIND_CPY, NULL, (PyObject *)self,
      self->l2p, self->l2_rem,
      self->linktype, self->ethertype, self->vlan_tag,
      self->l3p, self->l3_rem, self->proto,  self->dp, self->rem);
   // pltData_dump(redirect_obj, "*leaving icmp.get_redirect()");  //debug
   return (PyObject *)redirect_obj;
   }
set_read_only(redirect);

static PyGetSetDef ICMP_getseters[] = {
   {"type",
      (getter)get_type, (setter)set_type,
      "ICMP message type", NULL},
   {"code",
      (getter)get_code, (setter)set_code,
      "ICMP message code", NULL},
   {"checksum",
      (getter)get_checksum, (setter)set_checksum,
      "ICMP checksum", NULL},
   {"payload",
       (getter)get_payload, (setter)set_payload,
      "IP payload of ICMP", NULL},
   {"echo",
       (getter)get_echo, (setter)set_echo,
      "Echo subclass of ICMP", NULL},
   {"redirect",
       (getter)get_redirect, (setter)set_redirect,
      "Redirect subclass of ICMP", NULL},
   {NULL},  /* Sentinel */
   };

static PyMethodDef icmp_methods[] = {
   {NULL}  /* Sentinel */
   };

PyTypeObject IcmpType = {
   PV_PyObject_HEAD_INIT
   "IcmpObject",                /*tp_name*/
   sizeof(DataObject),          /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)icmp_dealloc,    /*tp_dealloc*/
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
   "PythonLibtrace ICMP",         /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   icmp_methods,                /* tp_methods */
   0,                           /* tp_members */
   ICMP_getseters,              /* tp_getset */
   &IpType,                     /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */ 
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)icmp_init,         /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)icmp_new,           /* tp_new */
   };

/* Echo class */

static void echo_dealloc(PyObject *self) {
   self->ob_type->tp_free((PyObject *)self);
   }

static PyObject *echo_new(PyTypeObject *type) {
   PyObject *self = (PyObject *)type->tp_alloc(type, 0);
   printf("echo_new(): self=%p\n", self);  fflush(stdout);
   return self;
   }

static int echo_init(PyObject *self) {
  printf("echo_init(): self=%p\n", self);  fflush(stdout);
   return 0;
   }

static PyObject *get_echo4_ident(DataObject *self, void *closure) {
    struct icmp *icmp = get_icmp(self, 6);
    if (!icmp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for type");  return NULL;
      }
   return PV_PyInt_FromLong((long)ntohs(icmp->un.echo.id));
   }
set_read_only(echo_ident);

static PyObject *get_echo4_sequence(DataObject *self, void *closure) {
    struct icmp *icmp = get_icmp(self, 8);
    if (!icmp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for type");  return NULL;
      }
   return PV_PyInt_FromLong((long)ntohs(icmp->un.echo.sequence));
   }
set_read_only(echo_sequence);

static PyGetSetDef ECHO_getseters[] = {
   {"ident",
      (getter)get_echo4_ident, (setter)set_echo_ident,
      "Echo ICMP message id", NULL},
   {"sequence",
      (getter)get_echo4_sequence, (setter)set_echo_sequence,
      "Echo ICMP message sequence", NULL},
   {NULL},  /* Sentinel */
   };

static PyMethodDef echo_methods[] = {
   {NULL}  /* Sentinel */
   };

PyTypeObject EchoType = {
   PV_PyObject_HEAD_INIT
   "EchoObject",                /*tp_name*/
   sizeof(DataObject),          /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)echo_dealloc,    /*tp_dealloc*/
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
   "PythonLibtrace ECHO",       /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   echo_methods,                /* tp_methods */
   0,                           /* tp_members */
   ECHO_getseters,              /* tp_getset */
   &IcmpType,                   /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */ 
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)echo_init,         /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)echo_new,           /* tp_new */
   };

/* Redirect class */

static void redirect_dealloc(PyObject *self) {
   self->ob_type->tp_free((PyObject *)self);
   }

static PyObject *redirect_new(PyTypeObject *type) {
   PyObject *self = (PyObject *)type->tp_alloc(type, 0);
   return self;
   }

static int redirect_init(PyObject *self) {
   return 0;
   }

static PyObject *get_gateway(DataObject *self, void *closure) {
    struct icmp *icmp = get_icmp(self, 8);
    if (!icmp) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for redirect.gateway");  return NULL;
      }
   uint8_t *gatewayp = (uint8_t *)&icmp->un.un_gateway;
   PyObject *ba = PyByteArray_FromStringAndSize((char *)gatewayp, 4);
   PyObject *pArgs = Py_BuildValue("iO", 4, ba);
   PyObject *r = PyObject_CallObject(ipp_new, pArgs);
   Py_DECREF(pArgs);  Py_DECREF(ba);
   return r;
   }
set_read_only(gateway);

static PyGetSetDef Redirect_getseters[] = {
   {"gateway",
      (getter)get_gateway, (setter)set_gateway,
      "Redirect geteway address", NULL},
   {NULL},  /* Sentinel */
   };

static PyMethodDef redirect_methods[] = {
   {NULL}  /* Sentinel */
   };

PyTypeObject RedirectType = {
   PV_PyObject_HEAD_INIT
   "RedirectObject",            /*tp_name*/
   sizeof(DataObject),          /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)redirect_dealloc,  /*tp_dealloc*/
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
   "PythonLibtrace REDIRECT",  /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   redirect_methods,            /* tp_methods */
   0,                           /* tp_members */
   Redirect_getseters,          /* tp_getset */
   &IcmpType,                   /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */ 
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)redirect_init,     /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)redirect_new,       /* tp_new */
   };

void initicmp(void) {
   if (PyType_Ready(&IcmpType) < 0) return;
   if (PyType_Ready(&EchoType) < 0) return;
   if (PyType_Ready(&RedirectType) < 0) return;

   Py_TYPE(&IcmpType) = &PyType_Type;
   Py_TYPE(&EchoType) = &PyType_Type;
   Py_TYPE(&RedirectType) = &PyType_Type;

   Py_INCREF(&IcmpType);
   PyModule_AddObject(plt_module, "icmp", (PyObject *)&IcmpType);
   Py_INCREF(&EchoType);
   PyModule_AddObject(plt_module, "echo", (PyObject *)&EchoType);
   Py_INCREF(&RedirectType);
   PyModule_AddObject(plt_module, "redirect", (PyObject *)&RedirectType);
   }
