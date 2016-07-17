/* 1653, Thu 18 Jul 13 (NZST)

   ippmodule.c: IPprefix class, useful stuff for
                IP addresses and prefixes

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

#include <arpa/inet.h>
#include "pv.h"

typedef struct {  /* Python stuff starts here */
   PyObject_HEAD
   PyObject *version; /* IP version (4 or 6) */
   PyObject *addr;    /* Address bytearray */
   PyObject *length;  /* Prefix length */
   } IPprefixObject;

static void IPprefix_dealloc(IPprefixObject* self) {
   Py_XDECREF(self->version);  Py_XDECREF(self->addr);
   Py_XDECREF(self->length);
   PV_free_self;
   }

#define PLTversion  "1.9"

#define IP4_ADDR_LEN   4
#define IP6_ADDR_LEN  16

#define IP4_LAST_BIT   31
#define IP6_LAST_BIT  127

uint8_t b_mask[8] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };
static char v6a[60];  /* IPprefix result (including /length) */

#define ntm 0  /* Use clib routines */
#if ntm
static char *strmov(char *d, const char *s) {
   while (*s != '\0') *d++ = *s++;
   return d;
   }

static char *v6addr_to_s(char *in6a) {
  /* Returns pointer to next byte in v6a 
      Code from NeTraMet's nmc_pars.c */
   char buf[10];  /* RFC 2373: IPv6 Address Architecture */
   char *d = v6a;
   char *a = (char *)in6a;
   int j, k, st,len, stx,lenx;
   uint32_t v, a2[8];

   stx = st = len = lenx = 0;
   /* Longest run of zero pairs: stx is its index, lenx is its length */
   for (k = j = 0; j != 16; j += 2) {
      v =  ntohs(*(uint16_t *)&a[j]);
      a2[k++] = v;          /* Build array of two-byte pairs */
      if (v == 0) ++len;
      else {
         if (len > lenx) {  /* Find longest run of zero pairs */
            stx = st;  lenx = len;
	    }
         st = k;  len = 0;
         }
      }
   if (len > lenx) {
      stx = st;  lenx = len;
      }
   if (lenx > 1 && stx == 0) {  /* Longest run at left  RFC 5952 */
      d = strmov(d, ":");  j = lenx;
      }
   else {
      sprintf(buf, "%x", a2[0]);
      d = strmov(d,buf);  j = 1;
      }
   for (; j < 8; ) {
      if (lenx > 1 && j == stx) {
         d = strmov(d,":");  j += lenx;
      } else {
         sprintf(buf, ":%x", a2[j]);
         d = strmov(d, buf);  ++j;
         }
      }
   if (j == stx+lenx) d = strmov(d, ":");  /* Longest run at right */
   
   *d = '\0';
   return d;
}

static int16_t get_nbr(char **str, int *rem, int *base) {
   char *s = *str;
   int len = *rem, b = *base, j,k, c, n;

   for (j = 0; j != len; ++j) {
      c = s[j];
      if (c == '.') {
 	 if (!b) b = 10;  break;
         if (b == 16) {
            PyErr_SetString(PyExc_ValueError,
               "Can't have . in IPv6 address!");
            return -1;
            }
         }
      if (c == ':') {
 	 if (!b) b = 16;  break;
         if (b == 10) {
            PyErr_SetString(PyExc_ValueError,
               "Can't have : in IPv4 address!");
            return -1;
            }
         }
      if (c == '/') break;
      if (!isdigit(c) && isxdigit(c)) {
 	 if (!b) { b = 16; }
         }
      if (b == 10 && !isdigit(c)) {
         PyErr_SetString(PyExc_ValueError,
            "Non-decimal digit in IPv4 address!");
         return -1;
         }
      else if (!isxdigit(c)) {
         PyErr_SetString(PyExc_ValueError,
            "Non-hex digit in IPv6 address!");
         return -1;
         }
      if (!isxdigit(c)) {
         PyErr_SetString(PyExc_ValueError,
            "Non-(hex)-digit found!");
         return -1;
         }
      }

   for (n = k = 0; k != j; ++k) {
      c = s[k];
      if (c >= '0' && c <= '9') n = n*b + (c-'0');
      else  if (c >= 'a' && c <= 'f') n = n*b + (10 + c-'a');
      else n = n*b + (10 + c-'A');
      }

   *str = &s[j];  *rem = len-j;  *base = b;
   return n;
   }
#endif

static PyObject *IPprefix_new(PyTypeObject *type, PyObject *args) {
   /* All the new() method has to do is to return an IPprefix
      object, the init() method sets its attribute values.
      The same tuple of args are passed to both new() and init()!
      We need to supply both */
   IPprefixObject *self = (IPprefixObject *)type->tp_alloc(type, 0);

   /* Need to check arguments here, _init() can't return a value */

   int ver = -1, plen = -1, alen, mx_plen;
   long as_sz;
   PyObject *addr_ba = NULL;
   char nt_addr[IP6_ADDR_LEN+1] =  /* Null-filled address value */
      {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0};
   char *addr_s;
   Py_ssize_t TupleSize = PyTuple_Size(args);
   switch (TupleSize) {
   case 1:
      if (!PyArg_ParseTuple(args, "i:IPprefix_new", &ver))
         return NULL;
      break;
   case 2:
      if (!PyArg_ParseTuple(args, "iO:IPprefix_new", &ver, &addr_ba))
         return NULL;
      break;
   case 3:
      if (!PyArg_ParseTuple(args, "iOi:IPprefix_new",
            &ver, &addr_ba, &plen))
         return NULL;
      break;
   default:
      PyErr_SetString(PyExc_AttributeError,
         "IPprefix_init expects 1, 2 or 3 arguments");
      return NULL;
      }

   if (ver != 4 && ver != 6) {
      PyErr_SetString(PyExc_ValueError, "version must be 4 or 6");
      Py_DECREF(self);  return NULL;
      }

   if (addr_ba && PyByteArray_CheckExact(addr_ba)) {
      as_sz = PyByteArray_Size(addr_ba);
      if (ver == 4 && as_sz > IP4_ADDR_LEN) {
         PyErr_SetString(PyExc_AttributeError,
           "IPprefix_init v4 address > 4 bytes");
         return NULL;
         }
      else if (as_sz > IP6_ADDR_LEN) {
         PyErr_SetString(PyExc_AttributeError,
           "IPprefix_init v6 address > 16 bytes");
         return NULL;
         }
      addr_s = PyByteArray_AsString(addr_ba);   
      memcpy(nt_addr, addr_s, as_sz);
   }
   else {
      PyErr_SetString(PyExc_ValueError,
         "IPprefix addr must be a bytearray");  return NULL;
      }

   alen = ver == 4 ? IP4_ADDR_LEN : IP6_ADDR_LEN;  /* Reqd size */
   mx_plen = alen*8;
   if (plen != -1) {  /* Length was specified */
      mx_plen = alen*8;
      if (plen < 1 || plen > mx_plen) {
         PyErr_SetString(PyExc_AttributeError,
            "IPprefix length too long for version");
	 Py_DECREF(self);  return NULL;
         }
      self->length = PV_PyInt_FromLong((long)plen);
      if (self->length == NULL) {
         Py_DECREF(self);  return NULL;
         }
      }

   /* Parameters OK, set attribute values */
   self->version = PV_PyInt_FromLong((long)ver);
   if (self->version == NULL) {
      Py_DECREF(self->length);  Py_DECREF(self);  return NULL;
      }
   self->addr = PyByteArray_FromStringAndSize(nt_addr, alen);
   if (self->addr == NULL) {
      Py_DECREF(self->version);  Py_DECREF(self->length);
      Py_DECREF(self);  return NULL;
      }
   return (PyObject *)self;
   }

static int IPprefix_init(IPprefixObject *self, PyObject *args) {
   /* Nothing left to initialise here! */
   return 0;
   }

static PyMemberDef IPprefixObject_members[] = {
   {"version", T_OBJECT_EX, offsetof(IPprefixObject, version), READONLY,
    "IPprefix version"},
   {"addr", T_OBJECT_EX, offsetof(IPprefixObject, addr), READONLY,
    "IPprefix addr"},
   {"length", T_OBJECT_EX, offsetof(IPprefixObject, length), 0,
    "IPprefix length"},
   {NULL}  /* Sentinel */
   };

static PyObject *IPprefix_width(IPprefixObject *self) {
   int s_len;
   PyObject *result;

   s_len = (int)PV_PyInt_AsLong(self->length);
   if (s_len == -1) {
      PyErr_SetString(PyExc_AttributeError, "IPprefix length is None");
      return NULL;
      }

   result = PV_PyInt_FromLong((long)(s_len - 1));
   if (result == NULL) return NULL;
   return result;
   }

static PyObject *IPprefix_equal(IPprefixObject *self, PyObject *args) {
   IPprefixObject *arg=NULL;
   int s_ver, a_ver, nb;
   char *sp, *ap;
   PyObject *result;

   if (!PyArg_ParseTuple(args, "O:IPprefix_equal", &arg))
      return NULL; 

   s_ver = (int)PV_PyInt_AsLong(self->version);
   a_ver = (int)PV_PyInt_AsLong(arg->version);
   if (s_ver != a_ver) {
      PyErr_SetString(PyExc_AttributeError, 
         "versions must be the same (4 or 6)");
      return NULL;
      }

   sp = PyByteArray_AsString(self->addr);
   ap = PyByteArray_AsString(arg->addr);
   nb = s_ver == 4 ? IP4_ADDR_LEN : IP6_ADDR_LEN;

   result =  strncmp(sp, ap, nb) == 0 ? Py_True : Py_False;
   Py_INCREF(result);  return result;
   }

static PyObject *IPprefix_hasbitset(
      IPprefixObject *self, PyObject *args) {
   int s_ver, bn, last_bit;
   char *sp;
   PyObject *result;

   if (!PyArg_ParseTuple(args, "i:IPprefix_hasbitset", &bn))
      return NULL; 

   s_ver = (int)PV_PyInt_AsLong(self->version);
   last_bit = s_ver == 4 ? IP4_LAST_BIT : IP6_LAST_BIT;
   if (bn < 0)  /* Special case: <root> node has bit_index -1 */
        /* Always returns true, so <root> stays at top of the tree */
        result = Py_True;
   else if (bn > last_bit)  /* Past last byte of key (string), always false */
      return Py_False;
   else {
      sp = PyByteArray_AsString(self->addr);
      result = (sp[bn/8] & b_mask[bn%8]) != 0 ? Py_True : Py_False;
      }
   Py_INCREF(result);  return result;
   }

static PyObject *IPprefix_fbd(IPprefixObject *self, PyObject *args) {
   IPprefixObject *arg=NULL;
   int j, r;

   if (!PyArg_ParseTuple(args, "O:IPprefix_fbd", &arg))
      return NULL; 

   int s_ver = (int)PV_PyInt_AsLong(self->version);
   int a_ver = (int)PV_PyInt_AsLong(arg->version);
   if (s_ver != a_ver) {
      PyErr_SetString(PyExc_AttributeError, 
         "versions must be the same (4 or 6)");
      return NULL;
      }

   int s_len = (int)PV_PyInt_AsLong(self->length);
   int a_len = (int)PV_PyInt_AsLong(arg->length);
   if (s_len == -1 || a_len == -1) {
     PyErr_SetString(PyExc_AttributeError, 
         "either or both lengths None");
      return NULL;
      }
   int min_len = s_len < a_len ? s_len : a_len;

   char *sp = PyByteArray_AsString(self->addr);
   char *ap = PyByteArray_AsString(arg->addr);

   int nb = s_ver == 4 ? IP4_ADDR_LEN : IP6_ADDR_LEN;
   for (j = 0; j != nb; ++j)
      if (ap[j] != sp[j]) break;
   r = j*8;
   if (r >= min_len)  /* They differ at or after min_len */
      return PV_PyInt_FromLong((long)min_len);
   unsigned char xor = ap[j] ^ sp[j];
   while ((xor & 0x80) == 0) {
      r += 1;  xor <<= 1;
      }
   if (r >= min_len) r = min_len;
   return PV_PyInt_FromLong((long)r);
   }

static PyObject *IPprefix_isprefix(
      IPprefixObject *self, PyObject *args) {
      /* self precedes or equals arg prefix */
   IPprefixObject *arg=NULL;
   int s_ver, a_ver, s_len, a_len, nb, j, r;
   char *sp, *ap, xor;
   PyObject *result;

   if (!PyArg_ParseTuple(args, "O:IPprefix_isprefix", &arg))
      return NULL; 

   s_ver = (int)PV_PyInt_AsLong(self->version);
   a_ver = (int)PV_PyInt_AsLong(arg->version);
   if (s_ver != a_ver) {
      PyErr_SetString(PyExc_AttributeError, 
         "versions must be the same (4 or 6)");
      return NULL;
      }
   s_len = (int)PV_PyInt_AsLong(self->length);
   a_len = (int)PV_PyInt_AsLong(arg->length);
   if (s_len == -1 || a_len == -1) {
     PyErr_SetString(PyExc_AttributeError, 
         "either or both lengths None");
      return NULL;
      }
   if (s_len > a_len) {  /* Widths not <= */
      result = Py_False;  Py_INCREF(result);  return result;
   }

   sp = PyByteArray_AsString(self->addr);
   ap = PyByteArray_AsString(arg->addr);
   nb = s_ver == 4 ? IP4_ADDR_LEN : IP6_ADDR_LEN;
   for (j = 0; j != nb; ++j)
      if (ap[j] != sp[j]) break;
   r = j*8; 
   if (r >= s_len) {  /* They differ at or after s_len */
      result = Py_True;
      Py_INCREF(result);  return result;
      }
   xor = ap[j] ^ sp[j];
   while ((xor & 0x80) == 0) {
      r += 1;  xor <<= 1;
      }
   result = r >= s_len ? Py_True : Py_False;
   Py_INCREF(result);  return result;
   }

static IPprefixObject *rfc1918o16=NULL, *rfc1918o12=NULL, *rfc1918o8=NULL;

static PyObject *IPprefix_isrfc1918(IPprefixObject *self) {
   int s_ver;
   PyObject *r, *so;

   s_ver = (int)PV_PyInt_AsLong(self->version);
   if (s_ver != 4) {
      r = Py_False;  Py_INCREF(r);  return r;
      }

   so = Py_BuildValue("(O)", self);  /* Make tuple for isprefix() args */
   r = IPprefix_isprefix(rfc1918o16, so);
   if (r == NULL) return NULL;
   if (r == Py_True) return r;
   r = IPprefix_isprefix(rfc1918o12, so);
   if (r == NULL) return NULL;
   if (r == Py_True) return r;
   r = IPprefix_isprefix(rfc1918o8, so);
   if (r == NULL) return NULL;
   Py_DECREF(so);
   return r;
   }

static PyObject *IPprefix_complement(IPprefixObject *self);

static PyMethodDef IPprefix_methods[] = {
   {"width", (PyCFunction)IPprefix_width, METH_NOARGS,
    "IPprefix.length-1" },
   {"equal", (PyCFunction)IPprefix_equal, METH_VARARGS,
    "Arg and self have the same version and addr" },
   {"has_bit_set", (PyCFunction)IPprefix_hasbitset, METH_VARARGS,
    "Self has specified bit == 1" },
   {"first_bit_different", (PyCFunction)IPprefix_fbd, METH_VARARGS,
    "(0-origin) bit position where IPprefixes differ" },
   {"complement", (PyCFunction)IPprefix_complement, METH_NOARGS,
    "Ones complement of self address" },
   {"is_prefix", (PyCFunction)IPprefix_isprefix, METH_VARARGS,
    "Self is a prefix of its arg IPprefix" },
   {"is_rfc1918", (PyCFunction)IPprefix_isrfc1918, METH_NOARGS,
    "True if self is an RFC1918 address" },
   {NULL}  /* Sentinel */
   };

static int IPprefix_setattr(
      IPprefixObject *self, char *name, PyObject *v) {
   int newlen, ver;
   if (strcmp(name, "length") == 0) {
      if (!PV_PyInt_Check(v)) {
         PyErr_SetString(PyExc_TypeError, "length must be an integer");
         return -1;
         }
      newlen = (int)PV_PyInt_AsLong(v);
      if (newlen < 1) {
         PyErr_SetString(PyExc_ValueError, "length must be > 0");
         return -1;
         }
      ver = (int)PV_PyInt_AsLong(self->version);
      if (ver == 4 && newlen > IP4_ADDR_LEN*8) {
         PyErr_SetString(PyExc_ValueError, "IPv4 length must be <= 32");
         return -1;
         }
      else if (ver == 6 && newlen > IP6_ADDR_LEN*8) {
         PyErr_SetString(PyExc_ValueError, "IPv6 length must be <= 128");
         return -1;
         }
      self->length = v;  /* Value OK */
      Py_INCREF(v);  /* self now has a copy of v! */
      return 0;
      }
   else {
      PyErr_SetString(PyExc_AttributeError, "version and addr are READONLY");
      return -1;
      }
   return -1;
   }

static PyObject *IPprefix_str(IPprefixObject *self) {
   int ver = (int)PV_PyInt_AsLong(self->version);
   int length = self->length == NULL ? -1 : (int)PV_PyInt_AsLong(self->length);
      /* PyInt_AsLong(x) returns -1 if x == NULL */

   if (self->addr == NULL) {
      if (length >= 0) sprintf(v6a, "0/%d", length);
      else sprintf(v6a, "0");
      }
   else {
      unsigned char *as = (unsigned char *)PyByteArray_AsString(self->addr);
#if !ntm
      if (ver == 4) inet_ntop(AF_INET, as, v6a, INET_ADDRSTRLEN);
      else {
	 inet_ntop(AF_INET6, as, v6a, INET6_ADDRSTRLEN);
	 /* RFC 5952 says you can't use :: in place of a single :0:
            libc on OSX 10.9 gets this wrong, so we check for this!
	    Nevil and Se-Young, Wed 10 Jun 15 (NZST) */
	 char *cp = strstr(v6a, "::");
	 if (cp) {
	    int j, nc;
	    for (j = nc = 0; v6a[j] != '\0'; j += 1)
	       if (v6a[j] == ':') nc += 1;
	    if (nc == 7) {
	       memmove(&cp[2], &cp[1], &v6a[strlen(v6a)] - cp);
	       cp[1] = '0';
	       }
	    }
         }
      if (length >= 0) {
	int len = (int)strlen(v6a);
         sprintf(&v6a[len], "/%u", length);
         }
#else
      if (ver == 4) {
         if (length < 0) sprintf(v6a, "%u.%u.%u.%u",
            as[0],as[1],as[2],as[3]);
         else sprintf(v6a, "%u.%u.%u.%u/%u",
            as[0],as[1],as[2],as[3], length);
         }
      else {
         char *v6e = v6addr_to_s((char *)as);
         if (length >= 0) sprintf(v6e, "/%u", length);
         }
#endif
      }

   return PV_PyString_FromString(v6a);
   }

static PyObject *IPprefix_richcompare(
      IPprefixObject *a, IPprefixObject *b, int op) {
   int va, vb, nb, sc, cmp, la, lb;
   const char *sa, *sb;
   PyObject *result;

   va = (int)PV_PyInt_AsLong(a->version);
   vb = (int)PV_PyInt_AsLong(b->version);
   if (va != vb) {
      PyErr_SetString(PyExc_AttributeError, 
         "versions must be the same (4 or 6)");
      return NULL;
      }

   nb = va == 4 ? IP4_ADDR_LEN : IP6_ADDR_LEN;
   sa = PyByteArray_AsString(a->addr);
   sb = PyByteArray_AsString(b->addr);
   // printf("ver=%d, a: len=%d, >%s<, b: len=%d, >%s<\n",
   //    va, strlen((char *)sa), sa, strlen((char *)sb), sb);
   sc = strncmp(sa, sb, nb);

   if (sc == 0) {  /* addr bytes the same */
      if (a->length != NULL && b->length != NULL) {
         la = (int)PV_PyInt_AsLong(a->length);
         lb = (int)PV_PyInt_AsLong(b->length);
         if (la != lb) sc = la > lb ? -1 : +1;
            /* longest prefix compares as less (more equal)*/
         //printf("sc == 0: la=%d, lb=%d, sc=> %d\n", la,lb, sc);
         }
      }

   switch (op) {
   case Py_LT:  cmp = sc <  0;  break;
   case Py_LE:  cmp = sc <= 0;  break;
   case Py_EQ:  cmp = sc == 0;  break;
   case Py_NE:  cmp = sc != 0;  break;
   case Py_GT:  cmp = sc >  0;  break;
   case Py_GE:  cmp = sc >= 0;  break;
   default:     return NULL;  /* Can't happen */
      }
   result = cmp ? Py_True : Py_False;
   Py_INCREF(result);
   return result;
   }

static PyTypeObject IPprefixType = {
   PV_PyObject_HEAD_INIT
   "ipp.IPprefix",              /*tp_name*/
   sizeof(IPprefixObject),      /*tp_basicsize*/
   0,                           /*tp_itemsize*/
   (destructor)IPprefix_dealloc, /*tp_dealloc*/
   0,                           /*tp_print*/
   0,                           /*tp_getattr*/
   (setattrfunc)IPprefix_setattr, /*tp_setattr*/
   0,                           /*tp_compare*/
   0,                           /*tp_repr*/
   0,                           /*tp_as_number*/
   0,                           /*tp_as_sequence*/
   0,                           /*tp_as_mapping*/
   0,                           /*tp_hash */
   0,                           /*tp_call*/
   (reprfunc)IPprefix_str,      /*tp_str*/
   0,                           /*tp_getattro*/
   0,                           /*tp_setattro (setattr works, this doesn't) */  
   0,                           /*tp_as_buffer*/
   Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
   "IPprefix objects",          /* tp_doc */
   0,		                /* tp_traverse */
   0,		                /* tp_clear */
   (richcmpfunc)IPprefix_richcompare,  /* tp_richcompare */
   0,		                /* tp_weaklistoffset */
   0,		                /* tp_iter */
   0,		                /* tp_iternext */
   IPprefix_methods,            /* tp_methods */
   IPprefixObject_members,      /* tp_members */
   0,                           /* tp_getset */
   0,                           /* tp_base */
   0,                           /* tp_dict */
   0,                           /* tp_descr_get */
   0,                           /* tp_descr_set */
   0,                           /* tp_dictoffset */
   (initproc)IPprefix_init,     /* tp_init */
   0,                           /* tp_alloc */
   (newfunc)IPprefix_new,       /* tp_new */
   };


static PyObject *IPprefix_complement(IPprefixObject *self) {
   int s_ver, s_len, nb, j;
   char *sp, a[IP6_ADDR_LEN];
   IPprefixObject *result;

   s_ver = (int)PV_PyInt_AsLong(self->version);
   nb = s_ver == 4 ? IP4_ADDR_LEN : IP6_ADDR_LEN;
   sp = PyByteArray_AsString(self->addr);
   s_len = (int)PV_PyInt_AsLong(self->length);
   for (j = 0; j != nb; ++j) a[j] = ~sp[j];

   result = (IPprefixObject *)IPprefixType.tp_alloc(&IPprefixType, 0);
   if (result != NULL) {
      result->version = PV_PyInt_FromLong((long)s_ver);
      if (result->version == NULL) {
         Py_DECREF(result);  return NULL;
         }
      result->addr = PyByteArray_FromStringAndSize(a, nb);
      if (result->addr == NULL) {
         Py_DECREF(result->version);  Py_DECREF(result);  return NULL;
         }
      if (s_len >= 0) { 
         result->length = PV_PyInt_FromLong((long)s_len);
         if (result->length == NULL) {
            Py_DECREF(result->version);  Py_DECREF(result->addr);
            Py_DECREF(result);  return NULL;
            }
         }
      }
   return (PyObject *)result;
   }

static IPprefixObject *IPprefix_from_s(PyObject *self, PyObject *args) {
   char *str = NULL;
   if (!PyArg_ParseTuple(args, "s:IPprefix_from_s", &str)) 
      return NULL; 

   char *endp = NULL;  unsigned char addr[16];
   int version = 0, addr_len, length = -1;
   IPprefixObject *result;

#if !ntm
   char *slashp = strchr(str, '/');
   if (slashp != NULL) {  /* Get width */
     length = (int)strtol(slashp+1, &endp, 10);
      if (endp == NULL) {
         PyErr_SetString(PyExc_ValueError,
            "Non-integer prefix legth");
         return NULL;
         }
      else if (length < 0) {
         PyErr_SetString(PyExc_ValueError,
            "Prefix legth must be >= 0");
         return NULL;
         }
      slashp[0] = '\0'; 
      }
   if (inet_pton(AF_INET, str, &addr)) {
      version = 4;  addr_len = 4;
      if (length > 32) {
         PyErr_SetString(PyExc_ValueError,
            "IPv4 length must be <= 32");
         return NULL;
         }
      }
   else if (inet_pton(AF_INET6, str, &addr)) {
      version = 6;  addr_len = 16;
      if (length > 128) {
         PyErr_SetString(PyExc_ValueError,
            "IPv4 length must be <= 128");
         return NULL;
         }
      }
   if (slashp != NULL) *slashp = '/';
   if (!version) {
      PyErr_SetString(PyExc_ValueError,
         "Not a valid IPv4 orIPv6 address");
      return NULL;
      }

#else
   cher *sp;
   int len, base, n, x, dcx, havedcx, y;
   uint8_t a[16], *a2p;  uint16_t a2[8];

   len = (int)strlen(str);
   memset(a, 0, sizeof(a));
   sp = str;
   havedcx = dcx = 0;
   if (sp[0] == ':') {
      if (sp[1] == ':') {
         base = 16; havedcx = 1;
         sp += 2;  len -= 2;
         }
      else {
         PyErr_SetString(PyExc_ValueError,
            "Non-hex digit in IPv6 address!");
         return NULL;
         }
   } else {
      base = 0;  havedcx = 0;
      }

   n = get_nbr(&sp, &len, &base);
   if (n == -1) return NULL;  /* Pass error back */

   if (base == 10) {  /* IPv4 prefix */   
      for (x = 0; x != 4; ++x) {
         if (n > 255) {
            PyErr_SetString(PyExc_ValueError,
               "Integer > 255 in IPv4 address!");
            return NULL;
            }
  	 a[x] = n;
         if (len == 0) break;
         sp += 1; len -= 1;
         n = get_nbr(&sp, &len, &base);
         if (n == -1) return NULL;
         if (len == 0 || *sp == '/') {
	    a[x+1] = n;  break;
  	    }
         }

      version = 4;
      addr = a;  addr_len = 4;
      if (len == 0) length = -1;
      else if (*sp == '/') {
         sp += 1; len -= 1;
         length = get_nbr(&sp, &len, &base);
         if (length == -1) return NULL;
         if (length > 32) {
            PyErr_SetString(PyExc_ValueError,
               "IPv4 length must be <= 32");            return NULL;
            }
      } else {
         PyErr_SetString(PyExc_ValueError,
            "More than 4 integers in IPv4 address!");
         return NULL;
         }
      }
   else if (base == 16) {  /* IPv6 prefix */
      memset(a2, 0, sizeof(a2));
      for (x = 0; x != 8; ++x) {
         if (n > 0xFFFF) {
            PyErr_SetString(PyExc_ValueError,
  	       "Integer > 0xFFFF in IPv6 address!");
            return NULL;
            }
   	 a2[x] = ntohs((uint16_t)n);  /* Nathan, 13 Aug 09 */
         if (len >= 2 && sp[1] == ':') {
	    if (havedcx) {
               PyErr_SetString(PyExc_ValueError,
                  "Can only have one :: in an IPv6 address!");
               return NULL;
               }
  	    dcx = x+1;  havedcx = 1;
	    sp += 2;  len -= 2;
  	    }
	 if (len == 0 || *sp == '/') {
	    x += 1;  a2[x] = ntohs((uint16_t)n); /* Nathan, 13 Aug 09 */
	    break;
	    }
         sp += 1; len -= 1;  /* Skip the delimiter */
         n = get_nbr(&sp, &len, &base);
         if (n == -1) return NULL;
         }
      a2p = (uint8_t *)a2;
      /* x = total pairs, dcx = pairs before :: */
      if (dcx >= 0) memcpy(a, a2p, dcx*2);
      y = (x-dcx)*2;  memcpy(a + (16-y), a2p + dcx*2, y);
      version = 6;
      addr = a;  addr_len = 16;
      if (len == 0) length = -1;
      else if (*sp == '/') {
         sp += 1; len -= 1;  base = 10;
         length = get_nbr(&sp, &len, &base);
         if (length == -1) return NULL;
         if (length > 128) {
            PyErr_SetString(PyExc_ValueError,
               "More than 8 hex numbers in IPv6 address!");
            return NULL;
            }
      } else {
         PyErr_SetString(PyExc_ValueError,
            "Non-hex digit in IPv6 address!");
         return NULL;
         }
      }
   else {
      PyErr_SetString(PyExc_ValueError,
         "Non-hex digit in IPv6 address!");
      return NULL;
   }
#endif

   result = (IPprefixObject *)IPprefixType.tp_alloc(&IPprefixType, 0);
   if (result != NULL) {
      result->version = PV_PyInt_FromLong((long)version);
      if (result->version == NULL) {
         Py_DECREF(result);  return NULL;
         }
      result->addr = PyByteArray_FromStringAndSize((char *)addr, addr_len);
      if (result->addr == NULL) {
         Py_DECREF(result);  return NULL;
         }
      if (length >= 0) { 
         result->length = PV_PyInt_FromLong((long)length);
         if (result->length == NULL) {
            Py_DECREF(result->addr);  Py_DECREF(result);  return NULL;
            }
         }
      }
   return result;
   }

static PyObject *IPprefix_version(IPprefixObject *self) {
   return Py_BuildValue("s", PLTversion);
   }

static PyMethodDef module_methods[] = {
   {"IPprefix", (PyCFunction)IPprefix_new, METH_VARARGS,  // Thu, 2 Apr 15 
    "Create an IPprefix object from ver,addr,len arguments"},
   {"from_s", (PyCFunction)IPprefix_from_s, METH_VARARGS,
    "Create an IPprefix object from a string"},
   {"version", (PyCFunction)IPprefix_version, METH_NOARGS,
    "IPprefix version" },

   {NULL}  /* Sentinel */
   };

#if PYTHON3
static PyModuleDef ipp_module = {
    PyModuleDef_HEAD_INIT, "ipp", "IPprefix module, creates the IPprefix type.",
            -1, module_methods, NULL, NULL, NULL, NULL
   };
#endif

#if PYTHON3
PyMODINIT_FUNC PyInit_ipp(void)  {
#define RETURN return m
#else
PyMODINIT_FUNC initipp(void)  {
#define RETURN return
#endif

   PyObject* m=NULL, *c;
   IPprefixObject *p;

   if (PyType_Ready(&IPprefixType) < 0)
      RETURN;

#if PYTHON3
   m = PyModule_Create(&ipp_module);
#else
   m = Py_InitModule3("ipp", module_methods,
         "IPprefix module, creates the IPprefix type.");
#endif
   if (m == NULL) RETURN;

   Py_INCREF(&IPprefixType);
   PyModule_AddObject(m, "IPprefix", (PyObject *)&IPprefixType);

   c = Py_BuildValue("(s)", "192.168.0.0/16");  if (c == NULL) RETURN;
   p = IPprefix_from_s(m, c);  if (p == NULL) RETURN;
   rfc1918o16 = p;  Py_INCREF(rfc1918o16);
   PyModule_AddObject(m, "rfc1918s16", (PyObject *)p);

   c = Py_BuildValue("(s)", "172.16.0.0/12");  if (c == NULL) RETURN;
   p = IPprefix_from_s(m, c);  if (p == NULL) RETURN;
   rfc1918o12 = p;  Py_INCREF(rfc1918o12);
   PyModule_AddObject(m, "rfc1918s12", (PyObject *)p);

   c = Py_BuildValue("(s)", "10.0.0.0/8");  if (c == NULL) RETURN;
   p = IPprefix_from_s(m, c);  if (p == NULL) RETURN;
   rfc1918o8 = p;  Py_INCREF(rfc1918o8);
   PyModule_AddObject(m, "rfc1918s8", (PyObject *)p);
   RETURN;
   }
