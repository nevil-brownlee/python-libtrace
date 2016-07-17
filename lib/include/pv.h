/* 1252, Wed 8 Apr 15 (NZST)

   python-libtrace: a Python module to make it easy to use libtrace
   Copyright (C) 2015 by Habib Naderi, U Auckland | WAND

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

#ifndef PV_H
#define PV_H

#include <patchlevel.h>

#define PYTHON3 PY_MAJOR_VERSION > 2

#if PYTHON3  /* Fixed (on Nevil's OSX 10.9 Mac), 11 Jun 15 (NZST) */
//#warning "Building for python 3 <<<<"
// was #define PV_free_self  self->ob_base.ob_type->tp_free((PyObject*)self)
#define PV_free_self  Py_TYPE(self)->tp_free((PyObject*)self)
#define PV_PyInt_AsLong(a) PyLong_AsLong(a)
#define PV_PyInt_FromLong(a) PyLong_FromLong(a)
#define PV_PyInt_Check(a) PyLong_Check(a)
#define PV_PyString_FromString(a) PyUnicode_FromString(a)
#define PV_PyString_FromStringAndSize(a, b) PyUnicode_FromStringAndSize(a, b)
#define PV_PyString_FromStringAndSize_bytes(a, b) PyBytes_FromStringAndSize(a, b)
#define PV_PyObject_HEAD_INIT   PyVarObject_HEAD_INIT(NULL, 0)

#else

#define PV_free_self  self->ob_type->tp_free((PyObject*)self)
#define PV_PyInt_AsLong(a) PyInt_AsLong(a)
#define PV_PyInt_FromLong(a) PyInt_FromLong(a)
#define PV_PyInt_Check(a) PyInt_Check(a)
#define PV_PyString_FromString(a) PyString_FromString(a)
#define PV_PyString_FromStringAndSize(a, b) PyString_FromStringAndSize(a, b)
#define PV_PyString_FromStringAndSize_bytes(a, b) PyString_FromStringAndSize(a, b)
#define PV_PyObject_HEAD_INIT   PyObject_HEAD_INIT(0)\
                                0,
#endif

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#if PYTHON3
#  define PyMODINIT_FUNC static PyObject *
#else
#  define PyMODINIT_FUNC void
#endif
#endif

#endif
