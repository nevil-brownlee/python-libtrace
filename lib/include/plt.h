/* 1509, Fri 21 Nov 14 (NZDT)
   1011, Tue  6 May 14 (NZST)
   1452, Fri 14 Mar 14 (PDT)
   1421, Fri  2 Aug 13 (CEST)

   plt.h: defines etc, and global declarations
                 for the python-libtrace libraries.

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

#include <arpa/inet.h>

#define PLTversion     "1.6"

#define RLT_KIND_PKT       1  /* data points to a libtrace_packet_t */
#define RLT_KIND_STR       2  /* data points to a C byte array */
#define RLT_KIND_CPY       3  /* data points to another (MOM) rlt_obj */
#define BAD_RLT_KIND(v)  (v < RLT_KIND_PKT || v > RLT_KIND_COPY)

#define RLT_TYPE_DATA      5  /* rlt_obj data types */
#define RLT_TYPE_PKT      10
#define RLT_TYPE_L2       20
#define RLT_TYPE_L3       30
#define RLT_TYPE_Internet 31
#define RLT_TYPE_IP       32
#define RLT_TYPE_IP6      33
#define RLT_TYPE_L4       40
#define RLT_TYPE_TCP      41
#define RLT_TYPE_UDP      42
#define RLT_TYPE_ICMP     43
#define RLT_TYPE_ICMP6    44
#define RLT_TYPE_L5       50

typedef struct {
   PyObject_HEAD
   int type;       /* Data type, RLT_TYPE values above */
   int kind;       /* Object kind, defined abve */
   void *data;     /* Pointer to the object's libtrace_packet_t or string */
   PyObject *mom;  /* Reference to original python object, used,
		        e.g., when we clone a libtrace pkt */
   void *l2p;      /* Pointer to link-layer header */
   int l2_rem;     /* Bytes remaining at layer 2 */
   int linktype;   /* link type from original pkt, so we
		        can use trace_get_payload_from_layer2() */
   int ethertype;  /* So we can see its network protocol */
   int vlan_tag;   /* 802.1Q tag, NULL if there isn't one */
   void *l3p;      /* Pointer to the object's Internet struct */
   int l3_rem;     /* Remaining bytes for encapsulating python object */
   int proto;      /* Transport protocol */
   void *dp;       /* Pointer to an object within a DataObject
                        e.g. to a libtrace_tcp_t in a packet */
   int rem;        /* Number of bytes in the object */
   } DataObject;

int pltData_set_fields(
   PyObject *object,
   int kind, void *data, PyObject *mom, // int linktype,
   int type, void *l3p, int l3_rem, void *dp, int rem);

DataObject *plt_new_object(  /* Make a new Data object */
   PyTypeObject *py_type,
   int type, int kind, void* data, PyObject *mom,
   void* l2p, int l2_rem, int linktype, int ethertype, int vlan_tag,
   void *l3p, int l3_rem, int proto,
   void *dp, int rem);

void pltData_dump(DataObject *self, const char *msg);

typedef struct {
   PyObject_HEAD
   int started;
   libtrace_t *tr;
   libtrace_packet_t *lt_pkt;
   DataObject *py_packet;
   } TraceObject;

typedef struct {
   PyObject_HEAD
   int started;
   libtrace_out_t *op;
   } OutputTraceObject;

typedef struct  {  /* In trace.c */
   PyObject_HEAD
   int used;
   libtrace_filter_t *flt;
   } FilterObject;

extern char plt_err_msg[120];  /* For building libtrace error messages */

#define set_err_msg(fmt, v1) \
   snprintf(plt_err_msg, sizeof(plt_err_msg), fmt, v1)
#define set_err_msg2(fmt, v1, v2) \
  snprintf(plt_err_msg, sizeof(plt_err_msg), fmt, v1, v2)

#define set_read_only(attrib) \
static int set_##attrib( \
      DataObject *self, PyObject *value, void *closure) { \
   PyErr_SetString(PyExc_TypeError, #attrib " is read_only"); \
   return -1; \
   }

#define fcs_decr(ltype) \
   ((ltype == TRACE_TYPE_ETH || ltype == TRACE_TYPE_80211) ? \
      4 : 0)

uint16_t checksum(void *buffer, uint16_t len);
int transport_checksum(DataObject *d, int reset_cks);

extern PyObject *plt_module;  /* PythonLibtrace module (i.e. this one!) */
extern PyObject *ipp_new;     /* IPprefix.IPprefix() function */
extern PyObject *datetime_datetime_obj;

extern PyObject *plt_exc_libtrace;  /* Error detected by libtrace */

extern PyTypeObject Neighbour6Type;
extern PyTypeObject Param6Type;
extern PyTypeObject Toobig6Type;
extern PyTypeObject Echo6Type;
extern PyTypeObject Icmp6Type;
extern PyTypeObject RedirectType;
extern PyTypeObject EchoType;
extern PyTypeObject IcmpType;
extern PyTypeObject TcpType;
extern PyTypeObject UdpType;
extern PyTypeObject Ip6Type;
extern PyTypeObject IpType;
extern PyTypeObject InternetType;
extern PyTypeObject TransportType;
extern PyTypeObject Layer3Type;
extern PyTypeObject Layer2Type;
extern PyTypeObject DataType;
extern PyTypeObject PacketType;
extern PyTypeObject TraceType;
extern PyTypeObject FilterType;
extern PyTypeObject OutputTraceType;
extern PyTypeObject IPflowType;

void inittrace(void);
void initoutputtrace(void);
void initpacket(void);
void initlayers(void);
void inittransport(void);
void initinternet(void);
void initip(void);
void initip6(void);
void inittcp(void);
void initudp(void);
void initicmp(void);
void initicmp6(void);
void initipflow(void);

void quack(int which);
