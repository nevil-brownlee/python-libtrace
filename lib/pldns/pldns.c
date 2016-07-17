/* 1717,  5 Jul 14 (NZST)

   pldns.c: python interface to NLnetLab's ldns C library

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

#include <stdint.h>
#include <string.h>

#include <Python.h>
#include "structmember.h"

#include <ldns/ldns.h>

#include "libtrace.h"
#include "plt.h"
#include "pv.h"

void quack(int x) {};  /* For gdb breakpoint */

typedef struct {  /* Python stuff starts here */
   PyObject_HEAD
   ldns_pkt *ldpkt;  /* Has pointers into actual (libtrace) packet */
   ldns_status status;
   } LdnsObject;

typedef struct {
   PyObject_HEAD
   ldns_rr *rr;  /* Has pointers into an LdnsObject */
   } LdnsRrObject; 

#if 0
   struct ldns_struct_rr {
      // Owner name, uncompressed:
     dns_rdf  *_owner;  // pointer to owning rr
      // Time to live:
      uint32_t  _ttl;
      //  Number of data fields:
      size_t _rd_count;
      //  the type of the RR. A, MX etc.:
      ldns_rr_type   _rr_type;
      //  Class of the resource record.:
      ldns_rr_class  _rr_class;
      /* everything in the rdata is in network order */
      // The array of rdata's:
      ldns_rdf   **_rdata_fields;
      bool      _rr_question;
      };
   typedef struct ldns_struct_rr ldns_rr;

ldns_get_rr_type_by_name("AAAA")
ldns_rr_type2str(const ldns_rr_type type)

size_t ldns_rdf_size(const ldns_rdf *rd)
ldns_rdf_type ldns_rdf_get_type(const ldns_rdf *rd)

ldns_rdf *ldns_rr_owner(const ldns_rr *rr)
char *ldns_rdf2str(const ldns_rdf *rdf)
size_t ldns_rr_rd_count(rr)  // gets number of rdata fields

ldns_rdf *ldns_rr_rdf(const ldns_rr *rr, size_t n)
   // get nth rdf fromm rr
ldns_pkt_rcode ldns_pkt_get_rcode(const ldns_pkt *packet)
char *ldns_pkt_rcode2str(ldns_pkt_rcode rcode)

uint8_t ldns_pkt_edns_extended_rcode(const ldns_pkt *packet)

uint16_t ldns_pkt_qdcount(const ldns_pkt *packet)  //questions
uint16_t ldns_pkt_ancount(const ldns_pkt *packet)  //answers
uint16_t ldns_pkt_nscount(const ldns_pkt *packet)  //authority records
uint16_t ldns_pkt_arcount(const ldns_pkt *packet)  //additional resords

#endif

PyObject* plt_exc_ldns;

#define ldns_read_only(attrib) \
static int set_##attrib( \
      LdnsObject *self, PyObject *value, void *closure) { \
   PyErr_SetString(PyExc_TypeError, #attrib " is read_only"); \
   return -1; \
   }


static void LdnsRr_dealloc(LdnsObject* self) {
   PV_free_self;
   }

static PyObject *LdnsRr_new(PyTypeObject *type, PyObject *args) {
   LdnsRrObject *self = (LdnsRrObject *)type->tp_alloc(type, 0);
   return (PyObject *)self;
   }

static int LdnsRr_init(LdnsObject *self, PyObject *args) {
   return 0;
   }

static PyObject *get_rr_owner(LdnsRrObject *self, void *closure) {
   ldns_rdf *owner = ldns_rr_owner(self->rr);
   char *owner_s = ldns_rdf2str(owner);
   PyObject *rr_owner =  PV_PyString_FromString(owner_s);
   if (rr_owner == NULL) {
      PyErr_SetString(PyExc_ValueError,
         "Failed to create owner string");  return NULL;
      }
   free(owner_s);
   return rr_owner;
   }
ldns_read_only(rr_owner);

static PyObject *get_rr_type(LdnsRrObject *self, void *closure) {
   ldns_rr_type type = ldns_rr_get_type(self->rr);
   PyObject *rr_type = PV_PyInt_FromLong((long)type);
   return rr_type;
   }
ldns_read_only(rr_type);

static PyObject *get_rr_ttl(LdnsRrObject *self, void *closure) {
   ldns_rr_type ttl = ldns_rr_ttl(self->rr);
   PyObject *rr_type = PV_PyInt_FromLong((long)ttl);
   return rr_type;
   }
ldns_read_only(rr_ttl);

static PyObject *get_rr_rdata(LdnsRrObject *self, void *closure) {
   unsigned long n_rdfs = ldns_rr_rd_count(self->rr);
   char **sa = malloc(n_rdfs*sizeof(char *));
   if (sa == NULL) {
      PyErr_SetString(plt_exc_ldns,
        "Couldn't malloc string array");  return NULL;
      }
   ldns_rdf *rdf;
   int sx;  char *s;
   unsigned long len, j, sz;
   for (sz = j = 0; j != n_rdfs; j+= 1) {
      rdf = ldns_rr_rdf(self->rr, j);
      s = ldns_rdf2str(rdf);
      len = strlen(s);  /* ldns_rdf_size() gives 'raw' size */
      sa[j] = s;
      sz += strlen(sa[j])+1;  /* Include trailing blank */
      }
   char *buf = malloc(sz);
   if (buf == NULL) {
      PyErr_SetString(plt_exc_ldns,
        "Couldn't malloc rdata string");  return NULL;
      }
   for (sx = j = 0; j != n_rdfs; j+= 1) {
      len = strlen(sa[j]);
      memcpy(&buf[sx], sa[j], len);   sx += len;
      buf[sx] = ' ';  sx += 1;  /* Blanks between fields */
      free(sa[j]);
      }
   buf[sx-1] = '\0';
   PyObject *rr_rdata =  PV_PyString_FromString(buf);
   if (rr_rdata == NULL) {
      PyErr_SetString(PyExc_ValueError,
         "Failed to create rdata string");  return NULL;
      }
   free(buf);
   return rr_rdata;
   }
ldns_read_only(rr_rdata);

static PyObject *get_rr_string(LdnsRrObject *self, void *closure) {
   char *rrs = ldns_rr2str(self->rr);
   unsigned long len = strlen(rrs);
   rrs[len-1] = '\0';  /* Remove trailing \n */
   PyObject *ps = PV_PyString_FromString(rrs);
   if (ps == NULL) {
      PyErr_SetString(PyExc_ValueError,
         "Failed to create rr string");  return NULL;
      }
   free(rrs);
   return ps;
   }
ldns_read_only(rr_string);

static PyGetSetDef LdnsRr_getseters[] = {
   {"owner",
      (getter)get_rr_owner, (setter)set_rr_owner,
      "RR owner", NULL},
   {"type",
      (getter)get_rr_type, (setter)set_rr_type,
      "RR type", NULL},
   {"ttl",
      (getter)get_rr_ttl, (setter)set_rr_ttl,
      "RR ttl", NULL},
   {"rdata",
      (getter)get_rr_rdata, (setter)set_rr_rdata,
      "RR rdata", NULL},
   {"str",
      (getter)get_rr_string, (setter)set_rr_string,
      "RR string", NULL},
   {NULL},  /* Sentinel */
   };

static PyMethodDef LdnsRr_methods[] = {
   {NULL}  /* Sentinel */
   };

static PyTypeObject LdnsRrType = {
   PV_PyObject_HEAD_INIT
   "pldns.LdnsRr",              /*tp_name*/
   sizeof(LdnsRrObject),        /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)LdnsRr_dealloc,  /*tp_dealloc*/
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
   "LdnsRr objects",            /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   LdnsRr_methods,              /* tp_methods */
   0,                           /* tp_members */
   LdnsRr_getseters,            /* tp_getset */
   0,                           /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)LdnsRr_init,       /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)LdnsRr_new,         /* tp_new */
   };


static void Ldns_dealloc(LdnsObject* self) {
   if (self->ldpkt != NULL) ldns_pkt_free(self->ldpkt);
   PV_free_self;
   }

static PyObject *Ldns_new(PyTypeObject *type, PyObject *args) {
   /* All the new() method has to do is to return an Ldns
      object, the init() method sets its attribute values.
      The same tuple of args are passed to both new() and init()!
      We need to supply both */
   LdnsObject *self = (LdnsObject *)type->tp_alloc(type, 0);
   self->ldpkt = NULL;
 
   DataObject *arg = NULL;
   if (!PyArg_ParseTuple(args, "O:LdnsObject", &arg)) {
      PyErr_SetString(PyExc_ValueError, "Expected an object");
      return NULL;
      }
   if (arg->kind != RLT_KIND_CPY || arg->type != RLT_TYPE_L5) {
      PyErr_SetString(PyExc_ValueError,
         "Expected a LEVEL_5 object");  return NULL;
      }
   uint8_t *ba_p = arg->dp;  int ba_sz = arg->rem;
#if 0
   printf("Ldns_init:\n   ba_sz = %d\n", ba_sz);
   int j;  printf("   %02x", ba_p[0]);
   for (j = 1; j != 16; j += 1) printf(" %02x", ba_p[j]);
   printf("\n");
#endif
   self->status = ldns_wire2pkt(&self->ldpkt, ba_p, ba_sz);
      /* mallocs an ldns_pkt */

   return (PyObject *)self;
   }

static int Ldns_init(LdnsObject *self, PyObject *args) {
   return 0;
   }

static PyObject *ldns_ok(LdnsObject *self) {
   PyObject *result = self->status == LDNS_STATUS_OK ? Py_True : Py_False;
   Py_INCREF(result);  return result;
   }

static PyObject *ldns_errorstr(LdnsObject *self, PyObject *args) {
   int errnbr = 0;
   if (!PyArg_ParseTuple(args, "i:ldns_errorstr", &errnbr)) {
      PyErr_SetString(PyExc_SystemError, "Expected an integer");
      return NULL;
      }
   const char *es = ldns_get_errorstr_by_id(errnbr);
   PyObject *ps = PV_PyString_FromString(es);
   if (ps == NULL) {
      PyErr_SetString(PyExc_ValueError,
        "Failed to create errnbr string");  return NULL;
      }
   return ps;
   }

static PyMethodDef Ldns_methods[] = {
   {"is_ok", (PyCFunction)ldns_ok, METH_NOARGS,
    "ldns_pkt is OK" },
   {"errorstr", (PyCFunction)ldns_errorstr, METH_VARARGS,
    "String ldns status" },
   {NULL}  /* Sentinel */
   };

#if 0
static PyObject *rr_list_to_tuple_list(ldns_rr_list *rr_list) {
   int lsz = ldns_rr_list_rr_count(rr_list);
   PyObject *plist =  PyList_New(lsz);  /* Create new list, lsz entries */
   if (plist == NULL) {
      PyErr_SetString(PyExc_ValueError,
         "Failed to create list for RRs");  return NULL;
      }
   int j;  for (j = 0;  j != lsz;  ++j) {
      ldns_rr *next_rr = ldns_rr_list_rr(rr_list, j);
      ldns_rdf *owner = ldns_rr_owner(next_rr);
      char *owner_s = ldns_rdf2str(owner);
      PyObject *rr_owner =  PV_PyString_FromString(owner_s);
      if (rr_owner == NULL) {
         PyErr_SetString(PyExc_ValueError,
            "Failed to create owner string");  return NULL;
         }
      ldns_rr_type type = ldns_rr_get_type(next_rr);
      PyObject *rr_type = PV_PyInt_FromLong((long)type);
      PyObject *tuple = PyTuple_Pack(2, rr_owner, rr_type);
      if (tuple == NULL) {
         PyErr_SetString(PyExc_ValueError,
            "Failed to create tuple");  return NULL;
         }
       PyList_SetItem(plist, j, tuple);
      free(owner_s);
      }
   return plist;
   }
#endif

static PyObject *pldns_rr_list(ldns_rr_list *rr_list) {
  unsigned long j, lsz = ldns_rr_list_rr_count(rr_list);
   PyObject *plist =  PyList_New(lsz);  /* Create new list, lsz entries */
   if (plist == NULL) {
      PyErr_SetString(PyExc_ValueError,
         "Failed to create list for RRs");  return NULL;
      }
   for (j = 0;  j != lsz;  ++j) {
      LdnsRrObject *prr = (LdnsRrObject *)LdnsRrType.tp_alloc(&LdnsRrType, 0);
      if (prr != NULL) {
         ldns_rr *next_rr = ldns_rr_list_rr(rr_list, j);
	 prr->rr = next_rr;
         }
      PyList_SetItem(plist, j, (PyObject *)prr);
      }
   return plist;
   }

static PyObject *get_status(LdnsObject *self, void *closure) {
   return PV_PyInt_FromLong((long)self->status);
      /* values in /usr/local/include/ldns/error.h */
   }
ldns_read_only(status);

static PyObject *get_ident(LdnsObject *self, void *closure) {
   return PV_PyInt_FromLong((long)ldns_pkt_id(self->ldpkt));
   }
ldns_read_only(ident);

static PyObject *get_is_response(LdnsObject *self, void *closure) {
   PyObject *result = ldns_pkt_qr(self->ldpkt) ? Py_True : Py_False;
   Py_INCREF(result);  return result;
   }
ldns_read_only(is_response);

static PyObject *get_opcode(LdnsObject *self, void *closure) {
   return PV_PyInt_FromLong((long)ldns_pkt_get_opcode(self->ldpkt));
   }
ldns_read_only(opcode);

static PyObject *get_rcode(LdnsObject *self, void *closure) {
   return PV_PyInt_FromLong((long)ldns_pkt_get_rcode(self->ldpkt));
   }
ldns_read_only(rcode);

static PyObject *get_response_type(LdnsObject *self, void *closure) {
   return PV_PyInt_FromLong((long)ldns_pkt_get_rcode(self->ldpkt));
   }
ldns_read_only(response_type);

static PyObject *get_query_rr_list(LdnsObject *self, void *closure) {
   uint16_t qdcount = ldns_pkt_qdcount(self->ldpkt);
   if (qdcount == 0) {
      PyObject *result = Py_None;  Py_INCREF(result);  return result; 
      }
   ldns_rr_list *q_list = ldns_pkt_question(self->ldpkt);
   return pldns_rr_list(q_list);
   }
ldns_read_only(query_rr_list);

static PyObject *get_answer_rr_list(LdnsObject *self, void *closure) {
   uint16_t ancount = ldns_pkt_ancount(self->ldpkt);
   if (ancount == 0) {
      PyObject *result = Py_None;  Py_INCREF(result);  return result; 
      }
   ldns_rr_list *an_list = ldns_pkt_answer(self->ldpkt);
   return pldns_rr_list(an_list);
   }
ldns_read_only(answer_rr_list);

static PyObject *get_authority_rr_list(LdnsObject *self, void *closure) {
   uint16_t arcount = ldns_pkt_qdcount(self->ldpkt);
   if (arcount == 0) {
      PyObject *result = Py_None;  Py_INCREF(result);  return result; 
      }
   ldns_rr_list *au_list = ldns_pkt_authority(self->ldpkt);
   return pldns_rr_list(au_list);
   }
ldns_read_only(authority_rr_list);

static PyObject *get_additional_rr_list(LdnsObject *self, void *closure) {
   uint16_t arcount = ldns_pkt_qdcount(self->ldpkt);
   if (arcount == 0) {
      PyObject *result = Py_None;  Py_INCREF(result);  return result; 
      }
   ldns_rr_list *ad_list = ldns_pkt_additional(self->ldpkt);
   return pldns_rr_list(ad_list);
   }
ldns_read_only(additional_rr_list);


static PyGetSetDef Ldns_getseters[] = {
   {"status",
      (getter)get_status, (setter)set_status,
      "ldns_pkt_status", NULL},
   {"ident",
      (getter)get_ident, (setter)set_ident,
      "dns transaction ID", NULL},
   {"is_response",
      (getter)get_is_response, (setter)set_is_response,
      "DNS response message", NULL},
   {"opcode",
      (getter)get_opcode, (setter)set_opcode,
      "DNS opcode", NULL},
   {"rcode",
      (getter)get_rcode, (setter)set_rcode,
      "DNS rcode", NULL},
   {"response_type",
      (getter)get_response_type, (setter)set_response_type,
      "DNS response code", NULL},

   {"query_rr_list",
      (getter)get_query_rr_list, (setter)set_query_rr_list,
      "List of query RRs", NULL},
   {"response_rr_list",
      (getter)get_answer_rr_list, (setter)set_answer_rr_list,
      "List of answer RRs", NULL},
   {"auth_rr_list",
      (getter)get_authority_rr_list, (setter)set_authority_rr_list,
      "List of authority RRs", NULL},
   {"addit_rr_list",
      (getter)get_additional_rr_list, (setter)set_additional_rr_list,
      "List of additional RRs", NULL},
   {NULL},  /* Sentinel */
   };

static PyTypeObject LdnsType = {
   PV_PyObject_HEAD_INIT
   "pldns.Ldns",                /*tp_name*/
   sizeof(LdnsObject),          /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)Ldns_dealloc,    /*tp_dealloc*/
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
   "Ldns objects",              /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   0,                           /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   Ldns_methods,                /* tp_methods */
   0,                           /* tp_members */
   Ldns_getseters,              /* tp_getset */
   0,                           /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)Ldns_init,         /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)Ldns_new,           /* tp_new */
   };


static PyObject *ldns_opcodestr(LdnsObject *self, PyObject *args) {
   int errnbr = 0;
   if (!PyArg_ParseTuple(args, "i:ldns_opcodestr", &errnbr)) {
      PyErr_SetString(PyExc_SystemError, "Expected an integer");
      return NULL;
      }
   const char *os = ldns_pkt_opcode2str(errnbr);
   PyObject *ps = PV_PyString_FromString(os);
   if (ps == NULL) {
      PyErr_SetString(PyExc_ValueError,
        "Failed to create opcode string");  return NULL;
      }
   return ps;
   }

static PyObject *ldns_rcodestr(LdnsObject *self, PyObject *args) {
   int errnbr = 0;
   if (!PyArg_ParseTuple(args, "i:ldns_rcodestr", &errnbr)) {
      PyErr_SetString(PyExc_SystemError, "Expected an integer");
      return NULL;
      }
   const char *rs = ldns_pkt_rcode2str(errnbr);
   PyObject *ps = PV_PyString_FromString(rs);
   if (ps == NULL) {
      PyErr_SetString(PyExc_ValueError,
        "Failed to create rcode string");  return NULL;
      }
   return ps;
   }

static PyObject *ldns_typestr(LdnsObject *self, PyObject *args) {
   int type = 0;
   if (!PyArg_ParseTuple(args, "i:ldns_typestr", &type)) {
      PyErr_SetString(PyExc_SystemError, "Expected an integer");
      return NULL;
      }
   const char *ts = ldns_rr_type2str(type);
   PyObject *ps = PV_PyString_FromString(ts);
   if (ps == NULL) {
      PyErr_SetString(PyExc_ValueError,
        "Failed to create type string");  return NULL;
      }
   return ps;
   }

static PyMethodDef module_methods[] = {
   {"opcodestr", (PyCFunction)ldns_opcodestr, METH_VARARGS,
    "String dns opcode" },
   {"rcodestr", (PyCFunction)ldns_rcodestr, METH_VARARGS,
    "String dns rcode" },
   {"typestr", (PyCFunction)ldns_typestr, METH_VARARGS,
    "String RR type" },
   {NULL}  /* Sentinel */
   };

#if PYTHON3
static PyModuleDef pldns_module = {
    PyModuleDef_HEAD_INIT, "pldns", "pldns module: ldns dns datagram decodes.",
            -1, module_methods, NULL, NULL, NULL, NULL
   };
#endif

#if PYTHON3
PyMODINIT_FUNC PyInit_pldns(void)  {
#define RETURN return m
#else
PyMODINIT_FUNC initpldns(void)  {
#define RETURN return
#endif

   PyObject *m=NULL;

   if (PyType_Ready(&LdnsType) < 0)
      RETURN;
   if (PyType_Ready(&LdnsRrType) < 0)
      RETURN;
#if PYTHON3
   m = PyModule_Create(&pldns_module);
#else
   m = Py_InitModule3("pldns", module_methods,
         "pldns module: ldns dns datagram decodes.");
#endif
   if (m == NULL) RETURN;

   Py_INCREF(&LdnsType);
   PyModule_AddObject(m, "ldns", (PyObject *)&LdnsType);
   Py_INCREF(&LdnsRrType);
   PyModule_AddObject(m, "ldnsrr", (PyObject *)&LdnsRrType);

   plt_exc_ldns = PyErr_NewException("pldns.ldns_exc", NULL, NULL);
   RETURN;
   }
