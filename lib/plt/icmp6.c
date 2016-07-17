/* 1458, Wed 21 May 14 (NZST)
   1452, Fri 14 Mar 14 (PDT)
   1519, Fri  2 Jan 14 (NZDT)

   icmp6.c: RubyLibtrace, python version!

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

/* ICMPv6 layouts from RFC 2463,4443

Return IPv6 object from byte 8 ...
 1  Dest unreachable
 2  Packet too big  (next-hop MTU in bytes 4-7)
 3  Time exceeded
 4  Parameter Problem  (Pointer into IPv6 pkt in bytes 4-7)

Return Data object from byte 8 ...
Echo req, reply
 128,129 Ident in bytes 2-3, seq nbr in 4-5, Data follows from byte 8

ICMP header extensions defined by RFC 4884

There are lots of other ICMPv6 types, a useful summary is at
  http://www.networksorcery.com/enp/protocol/icmpv6.htm

133  Router solicitation     133-137 = Neighbour Discovery, RFC 2461
134  Router advertisment
135  Neighbour solicitation  TA from byte 8
136  Neighbour advertisment  TA from byte 8
137  Redirect  */

struct icmp6 {
   uint8_t type;             /* message type */
   uint8_t code;             /* type sub-code */
   uint16_t checksum;
   union {
      struct {               /* 128,129: Echo */
         uint16_t id;
         uint16_t sequence;
         } echo;
      struct {                /* 1: Destination Unreachable */
         uint32_t reserved;
         libtrace_ip6_t ip6;  /* Original datagram */
         } unreachable;
     struct {                 /* 2: Packet too big */
         uint32_t mtu;
         libtrace_ip6_t ip6;  /* Original datagram */
         } toobig;
     struct {                 /* 4: Parameter problem */
         uint32_t pointer;
         libtrace_ip6_t ip6;  /* Original datagram */
         } param;
     struct {                 /* 134,135: Neighbour solicit/advert */
         uint32_t reserved;
         libtrace_ip6_t targ_ip6;  /* Target Address */
         libtrace_ip6_t dest_ip6;  /* Destintaion Address (137 redirect) */
         } neighbour;
      } un;
   };

static void icmp6_dealloc(PyObject *self) {
   self->ob_type->tp_free((PyObject *)self);
   }

static PyObject *icmp6_new(PyTypeObject *type, PyObject *args) {
   DataObject *arg=NULL;  uint32_t remaining;  uint8_t proto;
   uint8_t *l4p = NULL;
   PyArg_ParseTuple(args, "O", (PyObject *)&arg);
   if (PyObject_IsInstance((PyObject *)arg, (PyObject *)&DataType)) {
      if (arg->ethertype == 0x86DD) {
	 remaining = arg->l3_rem;
         l4p = trace_get_payload_from_ip6(
            (libtrace_ip6_t *)arg->l3p, &proto, &remaining);
         } 
      if (l4p && proto == 58) {
         if (remaining >= 2) {   /* Need at least type and code */
            Py_INCREF(arg);
    	    DataObject *icmp6_obj = plt_new_object(&Icmp6Type,
	       RLT_TYPE_ICMP6, RLT_KIND_CPY, arg->data, (PyObject *)arg,
 	       arg->l2p, arg->l2_rem,
               arg->linktype, arg->ethertype, arg->vlan_tag,
               arg->l3p, arg->l3_rem, 58,  l4p, remaining);
            //pltData_dump(icmp6_obj, "*leaving plt.icmp6(Data)");  //debug
            return (PyObject *)icmp6_obj;
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
   DataObject *icmp6_obj = plt_new_object(&Icmp6Type,
      RLT_TYPE_ICMP6, RLT_KIND_CPY, NULL, (PyObject *)arg,
      NULL, 0, 0, 0x086DD, 0,  NULL, 0, 1,  l4p, remaining);
   pltData_dump(icmp6_obj, "*leaving plt.icmp(ByteArray)");  //debug
   return (PyObject *)icmp6_obj;
   }

static int icmp6_init(DataObject *self, PyObject *args) {
   return 0;
   }

static struct icmp6 *get_icmp6(DataObject *op, int x) {
   /*  Python gets to objects vistheir PythonTypes, so we can
       use this for all the objects that use our icmp6 struct */
   if (op->rem < x) return NULL;
   struct icmp6 *icmp6 = op->dp;
   return icmp6;
   }

static PyObject *get_type(DataObject *self, void *closure) {
   struct icmp6 *icmp6 = get_icmp6(self, 1);
   if (!icmp6) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for type");  return NULL;
      }
   return PV_PyInt_FromLong((long)icmp6->type);
   }
set_read_only(type);

static PyObject *get_code(DataObject *self, void *closure) {
   struct icmp6 *icmp6 = get_icmp6(self, 2);
   if (!icmp6) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for code");  return NULL;
      }
   return PV_PyInt_FromLong((long)icmp6->code);
   }
set_read_only(code);

static PyObject *get_checksum(DataObject *self, void *closure) {
   struct icmp6 *icmp6 = get_icmp6(self, 4);
   if (!icmp6) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for checksum");  return NULL;
      }
   return PyLong_FromUnsignedLong((unsigned long)ntohs(icmp6->checksum));
   }
static int set_checksum(DataObject *self,
      PyObject *value, void *closure) {
   if (self->kind != RLT_KIND_PKT) {
      PyErr_SetString(PyExc_ValueError,
         "Object didn't come from a plt Packet");  return -1;
      }
   struct icmp6 *icmp6 = get_icmp6(self, 4); 
   if (!icmp6) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for icmp6 checksum");
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
   icmp6->checksum = ntohs((uint16_t)cks_v);
   return 0;
   }

static PyObject *get_payload(DataObject *self, void *closure) {
   struct icmp6 *icmp6 = get_icmp6(self, 12);
   if (!icmp6) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for payload");  return NULL;
      }
   PyTypeObject *py_type;  int rlt_type;
   switch (icmp6->type) {
   case 1:  /* Dest unreachable */
   case 2:  /* Packet too big (next-hop MTU in bytes 4-7) */
   case 3:  /* Time exceeded */
   case 4:  /* Parameter problem */
      py_type = &Ip6Type;  rlt_type = RLT_TYPE_IP6;
      break;
   default:
      py_type = &DataType;  rlt_type = RLT_TYPE_DATA;
      }
   Py_INCREF(self);
   DataObject *icmp6_obj = plt_new_object(py_type,
      rlt_type, RLT_KIND_CPY, NULL, (PyObject *)self,
      self->l2p, self->l2_rem,
      self->linktype, self->ethertype, self->vlan_tag,
      self->l3p, self->l3_rem, 58,  self->dp+8, self->rem-8);
   // pltData_dump(icmp6_obj, "*leaving icmp6.get_payload(Data)");  //debug
   return (PyObject *)icmp6_obj;
   }
set_read_only(payload);

static PyObject *get_echo(DataObject *self) {
   Py_INCREF(self);
   DataObject *echo_obj = plt_new_object(&Echo6Type,
      self->type, RLT_KIND_CPY, NULL, (PyObject *)self,
      self->l2p, self->l2_rem,
      self->linktype, self->ethertype, self->vlan_tag,
      self->l3p, self->l3_rem, self->proto,  self->dp, self->rem);
   // pltData_dump(echo_obj, "*leaving icmp6.get_echo()");  //debug
   return (PyObject *)echo_obj;
   }
set_read_only(echo); 

static PyObject *get_toobig(DataObject *self) {
   Py_INCREF(self);
   DataObject *toobig_obj = plt_new_object(&Toobig6Type,
      self->type, RLT_KIND_CPY, NULL, (PyObject *)self,
      self->l2p, self->l2_rem,
      self->linktype, self->ethertype, self->vlan_tag,
      self->l3p, self->l3_rem, self->proto,  self->dp, self->rem);
   // pltData_dump(toobig_obj, "*leaving icmp6.get_toobig()");  //debug
   return (PyObject *)toobig_obj;
   }
set_read_only(toobig);

static PyObject *get_param(DataObject *self) {
   Py_INCREF(self);
   DataObject *param_obj = plt_new_object(&Param6Type,
      self->type, RLT_KIND_CPY, NULL, (PyObject *)self,
      self->l2p, self->l2_rem,
      self->linktype, self->ethertype, self->vlan_tag,
      self->l3p, self->l3_rem, self->proto,  self->dp, self->rem);
   // pltData_dump(param_obj, "*leaving icmp6.get_param()");  //debug
   return (PyObject *)param_obj;
   }
set_read_only(param);

static PyObject *get_neighbour(DataObject *self) {
   Py_INCREF(self);
   DataObject *neighbour_obj = plt_new_object(&Neighbour6Type,
      self->type, RLT_KIND_CPY, NULL, (PyObject *)self,
      self->l2p, self->l2_rem,
      self->linktype, self->ethertype, self->vlan_tag,
      self->l3p, self->l3_rem, self->proto,  self->dp, self->rem);
   // pltData_dump(neighbour_obj, "*leaving icmp6.get_neighbour()");  //debug
   return (PyObject *)neighbour_obj;
   }
set_read_only(neighbour);

static PyGetSetDef ICMP6_getseters[] = {
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
      "IP payload of ICMP6", NULL},
   {"echo",
       (getter)get_echo, (setter)set_echo,
      "Echo subclass of ICMP6", NULL},
   {"toobig",
       (getter)get_toobig, (setter)set_toobig,
      "TooBig subclass of ICMP6", NULL},
   {"param",
       (getter)get_param, (setter)set_param,
      "Param subclass of ICMP6", NULL},
   {"neighbour",
       (getter)get_neighbour, (setter)set_neighbour,
      "Neighbour subclass of ICMP6", NULL},
   {NULL},  /* Sentinel */
   };

static PyMethodDef icmp6_methods[] = {
   {NULL}  /* Sentinel */
   };

PyTypeObject Icmp6Type = {
   PV_PyObject_HEAD_INIT
   "IcmpObject",                /*tp_name*/
   sizeof(DataObject),          /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)icmp6_dealloc,   /*tp_dealloc*/
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
   "PythonLibtrace ICMP6",      /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   icmp6_methods,                /* tp_methods */
   0,                           /* tp_members */
   ICMP6_getseters,             /* tp_getset */
   &Ip6Type,                    /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */ 
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)icmp6_init,        /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)icmp6_new,          /* tp_new */
   };

/* Echo class */

static void echo6_dealloc(PyObject *self) {
   self->ob_type->tp_free((PyObject *)self);
   }

static PyObject *echo6_new(PyTypeObject *type) {
   PyObject *self = (PyObject *)type->tp_alloc(type, 0);
   return self;
   }

static int echo6_init(PyObject *self) {
   return 0;
   }

static PyObject *get_echo6_ident(DataObject *self, void *closure) {
   struct icmp6 *icmp6 = get_icmp6(self, 6);
   if (!icmp6) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for echo.ident");  return NULL;
      }
   return PV_PyInt_FromLong((long)ntohs(icmp6->un.echo.id));
   }
set_read_only(echo6_ident);

static PyObject *get_echo6_sequence(DataObject *self, void *closure) {
   struct icmp6 *icmp6 = get_icmp6(self, 8);
   if (!icmp6) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for echo.sequence");  return NULL;
      }
   return PV_PyInt_FromLong((long)ntohs(icmp6->un.echo.sequence));
   }
set_read_only(echo6_sequence);

static PyGetSetDef echo6_getseters[] = {
   {"ident",
      (getter)get_echo6_ident, (setter)set_echo6_ident,
      "Echo ICMP message id", NULL},
   {"sequence",
      (getter)get_echo6_sequence, (setter)set_echo6_sequence,
      "Echo ICMP message sequence", NULL},
   {NULL},  /* Sentinel */
   };

static PyMethodDef echo6_methods[] = {
   {NULL}  /* Sentinel */
   };

PyTypeObject Echo6Type = {
   PV_PyObject_HEAD_INIT
   "EchoObject",                /*tp_name*/
   sizeof(DataObject),          /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)echo6_dealloc,   /*tp_dealloc*/
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
   "PythonLibtrace Echo6",       /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   echo6_methods,                /* tp_methods */
   0,                           /* tp_members */
   echo6_getseters,             /* tp_getset */
   &Icmp6Type,                  /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */ 
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)echo6_init,        /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)echo6_new,          /* tp_new */
   };

/* Toobig class */

static void toobig6_dealloc(PyObject *self) {
   self->ob_type->tp_free((PyObject *)self);
   }

static PyObject *toobig6_new(PyTypeObject *type) {
   PyObject *self = (PyObject *)type->tp_alloc(type, 0);
   return self;
   }

static int toobig6_init(PyObject *self) {
   return 0;
   }

static PyObject *get_mtu(DataObject *self, void *closure) {
   struct icmp6 *icmp6 = get_icmp6(self, 8);
   if (!icmp6) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for icmp6.toobig.mtu");  return NULL;
      }
   uint32_t *mtup = (uint32_t *)&icmp6->un.toobig.mtu;
   return PyLong_FromUnsignedLong((unsigned long)ntohl(*mtup));
   }
set_read_only(mtu);

static PyGetSetDef Toobig6_getseters[] = {
   {"mtu",
      (getter)get_mtu, (setter)set_mtu,
      "Redirect geteway address", NULL},
   {NULL},  /* Sentinel */
   };

static PyMethodDef toobig6_methods[] = {
   {NULL}  /* Sentinel */
   };

PyTypeObject Toobig6Type = {
   PV_PyObject_HEAD_INIT
   "RedirectObject",            /*tp_name*/
   sizeof(DataObject),          /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)toobig6_dealloc,  /*tp_dealloc*/
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
   "PythonLibtrace TOOBIG6",    /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   toobig6_methods,             /* tp_methods */
   0,                           /* tp_members */
   Toobig6_getseters,           /* tp_getset */
   &Icmp6Type,                  /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */ 
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)toobig6_init,      /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)toobig6_new,        /* tp_new */
   };

/* Param class */

static void param6_dealloc(PyObject *self) {
   self->ob_type->tp_free((PyObject *)self);
   }

static PyObject *param6_new(PyTypeObject *type) {
   PyObject *self = (PyObject *)type->tp_alloc(type, 0);
   return self;
   }

static int param6_init(PyObject *self) {
   return 0;
   }

static PyObject *get_pointer(DataObject *self, void *closure) {
   struct icmp6 *icmp6 = get_icmp6(self, 8);
   if (!icmp6) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for icmp6.param.pointer");  return NULL;
      }
   uint32_t *pp = (uint32_t *)&icmp6->un.param.pointer;
   return PyLong_FromUnsignedLong((unsigned long)ntohl(*pp));
   }
set_read_only(pointer);

static PyGetSetDef Param6_getseters[] = {
   {"pointer",
      (getter)get_pointer, (setter)set_pointer,
      "Redirect geteway address", NULL},
   {NULL},  /* Sentinel */
   };

static PyMethodDef param6_methods[] = {
   {NULL}  /* Sentinel */
   };

PyTypeObject Param6Type = {
   PV_PyObject_HEAD_INIT
   "RedirectObject",            /*tp_name*/
   sizeof(DataObject),          /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)param6_dealloc,  /*tp_dealloc*/
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
   "PythonLibtrace PARAM6",    /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   param6_methods,              /* tp_methods */
   0,                           /* tp_members */
   Param6_getseters,            /* tp_getset */
   &Icmp6Type,                  /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */ 
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)param6_init,       /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)param6_new,         /* tp_new */
   };

/* Neighbour class */

static void neighbour6_dealloc(PyObject *self) {
   self->ob_type->tp_free(self);
   }

static PyObject *neighbour6_new(PyTypeObject *type) {
   PyObject *self = (PyObject *)type->tp_alloc(type, 0);
   return self;
   }

static int neighbour6_init(PyObject *self) {
   return 0;
   }

static PyObject *get_target_prefix(DataObject *self, void *closure) {
   struct icmp6 *icmp6 = get_icmp6(self, 24);
   if (!icmp6) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for icmp.neighbour.target_prefix");  return NULL;
      }
   uint8_t *tp = (uint8_t *)&icmp6->un.neighbour.targ_ip6;
   PyObject *ba = PyByteArray_FromStringAndSize((char *)tp, 16);
   PyObject *pArgs = Py_BuildValue("iO", 6, ba);
   PyObject *r = PyObject_CallObject(ipp_new, pArgs);
   Py_DECREF(pArgs);  Py_DECREF(ba);
   return r;
  }
set_read_only(target_prefix);

static PyObject *get_dest_prefix(DataObject *self, void *closure) {
   struct icmp6 *icmp6 = get_icmp6(self, 40);
   if (!icmp6) {
      PyErr_SetString(PyExc_ValueError,
         "Data too short for icmp.neighbour.dest_prefix");  return NULL;
      }
   uint8_t *dp = (uint8_t *)&icmp6->un.neighbour.dest_ip6;
   PyObject *ba = PyByteArray_FromStringAndSize((char *)dp, 16);
   PyObject *pArgs = Py_BuildValue("iO", 6, ba);
   PyObject *r = PyObject_CallObject(ipp_new, pArgs);
   Py_DECREF(pArgs);  Py_DECREF(ba);
   return r;
  }
set_read_only(dest_prefix);

static PyGetSetDef Neighbour6_getseters[] = {
   {"target_prefix",
      (getter)get_target_prefix, (setter)set_target_prefix,
      "Neighbour target address", NULL},
   {"dest_prefix",
      (getter)get_dest_prefix, (setter)set_dest_prefix,
      "Neighbour destination address", NULL},
   {NULL},  /* Sentinel */
   };

static PyMethodDef neighbour6_methods[] = {
   {NULL}  /* Sentinel */
   };

PyTypeObject Neighbour6Type = {
   PV_PyObject_HEAD_INIT
   "RedirectObject",            /*tp_name*/
   sizeof(DataObject),          /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)neighbour6_dealloc,  /*tp_dealloc*/
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
   "PythonLibtrace NEIGHBOUR6", /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   neighbour6_methods,          /* tp_methods */
   0,                           /* tp_members */
   Neighbour6_getseters,        /* tp_getset */
   &Icmp6Type,                  /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */ 
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)neighbour6_init,   /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)neighbour6_new,     /* tp_new */
   };

void initicmp6(void) {
   if (PyType_Ready(&Icmp6Type) < 0) return;
   if (PyType_Ready(&Echo6Type) < 0) return;
   if (PyType_Ready(&Toobig6Type) < 0) return;
   if (PyType_Ready(&Param6Type) < 0) return;
   if (PyType_Ready(&Neighbour6Type) < 0) return;

   Py_TYPE(&Icmp6Type) = &PyType_Type;
   Py_TYPE(&Echo6Type) = &PyType_Type;
   Py_TYPE(&Toobig6Type) = &PyType_Type;
   Py_TYPE(&Param6Type) = &PyType_Type;
   Py_TYPE(&Neighbour6Type) = &PyType_Type;

   Py_INCREF(&Icmp6Type);
   PyModule_AddObject(plt_module, "icmp6", (PyObject *)&Icmp6Type);
   Py_INCREF(&Echo6Type);
   PyModule_AddObject(plt_module, "echo6", (PyObject *)&Echo6Type);
   Py_INCREF(&Toobig6Type);
   PyModule_AddObject(plt_module, "toobig6", (PyObject *)&Toobig6Type);
   Py_INCREF(&Param6Type);
   PyModule_AddObject(plt_module, "param6", (PyObject *)&Param6Type);
   Py_INCREF(&Neighbour6Type);
   PyModule_AddObject(plt_module, "neighbour6", (PyObject *)&Neighbour6Type);
   }
