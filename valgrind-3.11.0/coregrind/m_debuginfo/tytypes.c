
/*--------------------------------------------------------------------*/
/*--- Representation of source level types.              tytypes.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2008-2015 OpenWorks LLP
      info@open-works.co.uk

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.

   Neither the names of the U.S. Department of Energy nor the
   University of California nor the names of its contributors may be
   used to endorse or promote products derived from this software
   without prior written permission.
*/

#include "pub_core_basics.h"
#include "pub_core_debuginfo.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcprint.h"
#include "pub_core_xarray.h"   /* to keep priv_tytypes.h happy */

#include "priv_misc.h"         /* dinfo_zalloc/free/strdup */
#include "priv_d3basics.h"     /* ML_(evaluate_Dwarf3_Expr) et al */
#include "priv_tytypes.h"      /* self */

#include "pub_core_execontext.h" // pgbovine
#include "pub_core_addrinfo.h" // pgbovine
#include "pub_core_oset.h" // pgbovine

#include "pub_tool_mallocfree.h" // pgbovine - potential abstration violation with _tool_.h include, ergh

// pgbovine - super hacky -- INLINED json.h and json.c from here:
// http://git.ozlabs.org/?p=ccan;a=tree;f=ccan/json;hb=HEAD
// http://stackoverflow.com/a/6588482

// BEGIN json.h

/*
  Copyright (C) 2011 Joseph A. Adams (joeyadams3.14159@gmail.com)
  All rights reserved.

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#ifndef CCAN_JSON_H
#define CCAN_JSON_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
  JSON_NULL,
  JSON_BOOL,
  JSON_STRING,
  JSON_NUMBER,
  JSON_ARRAY,
  JSON_OBJECT,
} JsonTag;

typedef struct JsonNode JsonNode;

struct JsonNode
{
  /* only if parent is an object or array (NULL otherwise) */
  JsonNode *parent;
  JsonNode *prev, *next;
  
  /* only if parent is an object (NULL otherwise) */
  char *key; /* Must be valid UTF-8. */
  
  JsonTag tag;
  union {
    /* JSON_BOOL */
    bool bool_;
    
    /* JSON_STRING */
    char *string_; /* Must be valid UTF-8. */
    
    /* JSON_NUMBER */
    double number_;
    
    /* JSON_ARRAY */
    /* JSON_OBJECT */
    struct {
      JsonNode *head, *tail;
    } children;
  };
};

/*** Encoding, decoding, and validation ***/

JsonNode   *json_decode         (const char *json);
char       *json_encode         (const JsonNode *node);
char       *json_encode_string  (const char *str);
char       *json_stringify      (const JsonNode *node, const char *space);
void        json_delete         (JsonNode *node);

bool        json_validate       (const char *json);

/*** Lookup and traversal ***/

JsonNode   *json_find_element   (JsonNode *array, int index);
JsonNode   *json_find_member    (JsonNode *object, const char *key);

JsonNode   *json_first_child    (const JsonNode *node);

#define json_foreach(i, object_or_array)            \
  for ((i) = json_first_child(object_or_array);   \
     (i) != NULL;                               \
     (i) = (i)->next)

/*** Construction and manipulation ***/

JsonNode *json_mknull(void);
JsonNode *json_mkbool(bool b);
JsonNode *json_mkstring(const char *s);
JsonNode *json_mknumber(double n);
JsonNode *json_mkarray(void);
JsonNode *json_mkobject(void);

void json_append_element(JsonNode *array, JsonNode *element);
void json_prepend_element(JsonNode *array, JsonNode *element);
void json_append_member(JsonNode *object, const char *key, JsonNode *value);
void json_prepend_member(JsonNode *object, const char *key, JsonNode *value);

void json_remove_from_parent(JsonNode *node);

/*** Debugging ***/

/*
 * Look for structure and encoding problems in a JsonNode or its descendents.
 *
 * If a problem is detected, return false, writing a description of the problem
 * to errmsg (unless errmsg is NULL).
 */
bool json_check(const JsonNode *node, char errmsg[256]);

#endif

// END json.h

// BEGIN json.c -- changed slightly to use Valgrind's libc functions

/*
  Copyright (C) 2011 Joseph A. Adams (joeyadams3.14159@gmail.com)
  All rights reserved.

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#include <stdint.h>

#define out_of_memory() do {                    \
    VG_(printf)("JSON lib: Out of memory.\n");    \
    vg_assert(0);                     \
  } while (0)

/* Sadly, strdup is not portable. */
static char *json_strdup(const char *str)
{
  char *ret = (char*) VG_(malloc)("json_strdup", VG_(strlen)(str) + 1);
  if (ret == NULL)
    out_of_memory();
  VG_(strcpy)(ret, str);
  return ret;
}

/* String buffer */

typedef struct
{
  char *cur;
  char *end;
  char *start;
} SB;

static void sb_init(SB *sb)
{
  sb->start = (char*) VG_(malloc)("sb_init", 17);
  if (sb->start == NULL)
    out_of_memory();
  sb->cur = sb->start;
  sb->end = sb->start + 16;
}

/* sb and need may be evaluated multiple times. */
#define sb_need(sb, need) do {                  \
    if ((sb)->end - (sb)->cur < (need))     \
      sb_grow(sb, need);                  \
  } while (0)

static void sb_grow(SB *sb, int need)
{
  size_t length = sb->cur - sb->start;
  size_t alloc = sb->end - sb->start;
  
  do {
    alloc *= 2;
  } while (alloc < length + need);
  
  sb->start = (char*) VG_(realloc)("sb_grow", sb->start, alloc + 1);
  if (sb->start == NULL)
    out_of_memory();
  sb->cur = sb->start + length;
  sb->end = sb->start + alloc;
}

static void sb_put(SB *sb, const char *bytes, int count)
{
  sb_need(sb, count);
  VG_(memcpy)(sb->cur, bytes, count);
  sb->cur += count;
}

#define sb_putc(sb, c) do {         \
    if ((sb)->cur >= (sb)->end) \
      sb_grow(sb, 1);         \
    *(sb)->cur++ = (c);         \
  } while (0)

static void sb_puts(SB *sb, const char *str)
{
  sb_put(sb, str, VG_(strlen)(str));
}

static char *sb_finish(SB *sb)
{
  *sb->cur = 0;
  vg_assert(sb->start <= sb->cur && VG_(strlen)(sb->start) == (size_t)(sb->cur - sb->start));
  return sb->start;
}

static void sb_free(SB *sb)
{
  VG_(free)(sb->start);
}

/*
 * Unicode helper functions
 *
 * These are taken from the ccan/charset module and customized a bit.
 * Putting them here means the compiler can (choose to) inline them,
 * and it keeps ccan/json from having a dependency.
 */

/*
 * Type for Unicode codepoints.
 * We need our own because wchar_t might be 16 bits.
 */
typedef uint32_t uchar_t;

/*
 * Validate a single UTF-8 character starting at @s.
 * The string must be null-terminated.
 *
 * If it's valid, return its length (1 thru 4).
 * If it's invalid or clipped, return 0.
 *
 * This function implements the syntax given in RFC3629, which is
 * the same as that given in The Unicode Standard, Version 6.0.
 *
 * It has the following properties:
 *
 *  * All codepoints U+0000..U+10FFFF may be encoded,
 *    except for U+D800..U+DFFF, which are reserved
 *    for UTF-16 surrogate pair encoding.
 *  * UTF-8 byte sequences longer than 4 bytes are not permitted,
 *    as they exceed the range of Unicode.
 *  * The sixty-six Unicode "non-characters" are permitted
 *    (namely, U+FDD0..U+FDEF, U+xxFFFE, and U+xxFFFF).
 */
static int utf8_validate_cz(const char *s)
{
  unsigned char c = *s++;
  
  if (c <= 0x7F) {        /* 00..7F */
    return 1;
  } else if (c <= 0xC1) { /* 80..C1 */
    /* Disallow overlong 2-byte sequence. */
    return 0;
  } else if (c <= 0xDF) { /* C2..DF */
    /* Make sure subsequent byte is in the range 0x80..0xBF. */
    if (((unsigned char)*s++ & 0xC0) != 0x80)
      return 0;
    
    return 2;
  } else if (c <= 0xEF) { /* E0..EF */
    /* Disallow overlong 3-byte sequence. */
    if (c == 0xE0 && (unsigned char)*s < 0xA0)
      return 0;
    
    /* Disallow U+D800..U+DFFF. */
    if (c == 0xED && (unsigned char)*s > 0x9F)
      return 0;
    
    /* Make sure subsequent bytes are in the range 0x80..0xBF. */
    if (((unsigned char)*s++ & 0xC0) != 0x80)
      return 0;
    if (((unsigned char)*s++ & 0xC0) != 0x80)
      return 0;
    
    return 3;
  } else if (c <= 0xF4) { /* F0..F4 */
    /* Disallow overlong 4-byte sequence. */
    if (c == 0xF0 && (unsigned char)*s < 0x90)
      return 0;
    
    /* Disallow codepoints beyond U+10FFFF. */
    if (c == 0xF4 && (unsigned char)*s > 0x8F)
      return 0;
    
    /* Make sure subsequent bytes are in the range 0x80..0xBF. */
    if (((unsigned char)*s++ & 0xC0) != 0x80)
      return 0;
    if (((unsigned char)*s++ & 0xC0) != 0x80)
      return 0;
    if (((unsigned char)*s++ & 0xC0) != 0x80)
      return 0;
    
    return 4;
  } else {                /* F5..FF */
    return 0;
  }
}

/* Validate a null-terminated UTF-8 string. */
static bool utf8_validate(const char *s)
{
  int len;
  
  for (; *s != 0; s += len) {
    len = utf8_validate_cz(s);
    if (len == 0)
      return false;
  }
  
  return true;
}

/*
 * Read a single UTF-8 character starting at @s,
 * returning the length, in bytes, of the character read.
 *
 * This function assumes input is valid UTF-8,
 * and that there are enough characters in front of @s.
 */
static int utf8_read_char(const char *s, uchar_t *out)
{
  const unsigned char *c = (const unsigned char*) s;
  
  vg_assert(utf8_validate_cz(s));

  if (c[0] <= 0x7F) {
    /* 00..7F */
    *out = c[0];
    return 1;
  } else if (c[0] <= 0xDF) {
    /* C2..DF (unless input is invalid) */
    *out = ((uchar_t)c[0] & 0x1F) << 6 |
           ((uchar_t)c[1] & 0x3F);
    return 2;
  } else if (c[0] <= 0xEF) {
    /* E0..EF */
    *out = ((uchar_t)c[0] &  0xF) << 12 |
           ((uchar_t)c[1] & 0x3F) << 6  |
           ((uchar_t)c[2] & 0x3F);
    return 3;
  } else {
    /* F0..F4 (unless input is invalid) */
    *out = ((uchar_t)c[0] &  0x7) << 18 |
           ((uchar_t)c[1] & 0x3F) << 12 |
           ((uchar_t)c[2] & 0x3F) << 6  |
           ((uchar_t)c[3] & 0x3F);
    return 4;
  }
}

/*
 * Write a single UTF-8 character to @s,
 * returning the length, in bytes, of the character written.
 *
 * @unicode must be U+0000..U+10FFFF, but not U+D800..U+DFFF.
 *
 * This function will write up to 4 bytes to @out.
 */
static int utf8_write_char(uchar_t unicode, char *out)
{
  unsigned char *o = (unsigned char*) out;
  
  vg_assert(unicode <= 0x10FFFF && !(unicode >= 0xD800 && unicode <= 0xDFFF));

  if (unicode <= 0x7F) {
    /* U+0000..U+007F */
    *o++ = unicode;
    return 1;
  } else if (unicode <= 0x7FF) {
    /* U+0080..U+07FF */
    *o++ = 0xC0 | unicode >> 6;
    *o++ = 0x80 | (unicode & 0x3F);
    return 2;
  } else if (unicode <= 0xFFFF) {
    /* U+0800..U+FFFF */
    *o++ = 0xE0 | unicode >> 12;
    *o++ = 0x80 | (unicode >> 6 & 0x3F);
    *o++ = 0x80 | (unicode & 0x3F);
    return 3;
  } else {
    /* U+10000..U+10FFFF */
    *o++ = 0xF0 | unicode >> 18;
    *o++ = 0x80 | (unicode >> 12 & 0x3F);
    *o++ = 0x80 | (unicode >> 6 & 0x3F);
    *o++ = 0x80 | (unicode & 0x3F);
    return 4;
  }
}

/*
 * Compute the Unicode codepoint of a UTF-16 surrogate pair.
 *
 * @uc should be 0xD800..0xDBFF, and @lc should be 0xDC00..0xDFFF.
 * If they aren't, this function returns false.
 */
static bool from_surrogate_pair(uint16_t uc, uint16_t lc, uchar_t *unicode)
{
  if (uc >= 0xD800 && uc <= 0xDBFF && lc >= 0xDC00 && lc <= 0xDFFF) {
    *unicode = 0x10000 + ((((uchar_t)uc & 0x3FF) << 10) | (lc & 0x3FF));
    return true;
  } else {
    return false;
  }
}

/*
 * Construct a UTF-16 surrogate pair given a Unicode codepoint.
 *
 * @unicode must be U+10000..U+10FFFF.
 */
static void to_surrogate_pair(uchar_t unicode, uint16_t *uc, uint16_t *lc)
{
  uchar_t n;
  
  vg_assert(unicode >= 0x10000 && unicode <= 0x10FFFF);
  
  n = unicode - 0x10000;
  *uc = ((n >> 10) & 0x3FF) | 0xD800;
  *lc = (n & 0x3FF) | 0xDC00;
}

#define is_space(c) ((c) == '\t' || (c) == '\n' || (c) == '\r' || (c) == ' ')
#define is_digit(c) ((c) >= '0' && (c) <= '9')

static bool parse_value     (const char **sp, JsonNode        **out);
static bool parse_string    (const char **sp, char            **out);
static bool parse_number    (const char **sp, double           *out);
static bool parse_array     (const char **sp, JsonNode        **out);
static bool parse_object    (const char **sp, JsonNode        **out);
static bool parse_hex16     (const char **sp, uint16_t         *out);

static bool expect_literal  (const char **sp, const char *str);
static void skip_space      (const char **sp);

static void emit_value              (SB *out, const JsonNode *node);
static void emit_value_indented     (SB *out, const JsonNode *node, const char *space, int indent_level);
static void emit_string             (SB *out, const char *str);
static void emit_number             (SB *out, double num);
static void emit_array              (SB *out, const JsonNode *array);
static void emit_array_indented     (SB *out, const JsonNode *array, const char *space, int indent_level);
static void emit_object             (SB *out, const JsonNode *object);
static void emit_object_indented    (SB *out, const JsonNode *object, const char *space, int indent_level);

static int write_hex16(char *out, uint16_t val);

static JsonNode *mknode(JsonTag tag);
static void append_node(JsonNode *parent, JsonNode *child);
static void prepend_node(JsonNode *parent, JsonNode *child);
static void append_member(JsonNode *object, char *key, JsonNode *value);

/* Assertion-friendly validity checks */
static bool tag_is_valid(unsigned int tag);
static bool number_is_valid(const char *num);

JsonNode *json_decode(const char *json)
{
  const char *s = json;
  JsonNode *ret;
  
  skip_space(&s);
  if (!parse_value(&s, &ret))
    return NULL;
  
  skip_space(&s);
  if (*s != 0) {
    json_delete(ret);
    return NULL;
  }
  
  return ret;
}

char *json_encode(const JsonNode *node)
{
  return json_stringify(node, NULL);
}

char *json_encode_string(const char *str)
{
  SB sb;
  sb_init(&sb);
  
  emit_string(&sb, str);
  
  return sb_finish(&sb);
}

char *json_stringify(const JsonNode *node, const char *space)
{
  SB sb;
  sb_init(&sb);
  
  if (space != NULL)
    emit_value_indented(&sb, node, space, 0);
  else
    emit_value(&sb, node);
  
  return sb_finish(&sb);
}

void json_delete(JsonNode *node)
{
  if (node != NULL) {
    json_remove_from_parent(node);
    
    switch (node->tag) {
      case JSON_STRING:
        VG_(free)(node->string_);
        break;
      case JSON_ARRAY:
      case JSON_OBJECT:
      {
        JsonNode *child, *next;
        for (child = node->children.head; child != NULL; child = next) {
          next = child->next;
          json_delete(child);
        }
        break;
      }
      default:;
    }
    
    VG_(free)(node);
  }
}

bool json_validate(const char *json)
{
  const char *s = json;
  
  skip_space(&s);
  if (!parse_value(&s, NULL))
    return false;
  
  skip_space(&s);
  if (*s != 0)
    return false;
  
  return true;
}

JsonNode *json_find_element(JsonNode *array, int index)
{
  JsonNode *element;
  int i = 0;
  
  if (array == NULL || array->tag != JSON_ARRAY)
    return NULL;
  
  json_foreach(element, array) {
    if (i == index)
      return element;
    i++;
  }
  
  return NULL;
}

JsonNode *json_find_member(JsonNode *object, const char *name)
{
  JsonNode *member;
  
  if (object == NULL || object->tag != JSON_OBJECT)
    return NULL;
  
  json_foreach(member, object)
    if (VG_(strcmp)(member->key, name) == 0)
      return member;
  
  return NULL;
}

JsonNode *json_first_child(const JsonNode *node)
{
  if (node != NULL && (node->tag == JSON_ARRAY || node->tag == JSON_OBJECT))
    return node->children.head;
  return NULL;
}

static JsonNode *mknode(JsonTag tag)
{
  JsonNode *ret = (JsonNode*) VG_(calloc)("mknode", 1, sizeof(JsonNode));
  if (ret == NULL)
    out_of_memory();
  ret->tag = tag;
  return ret;
}

JsonNode *json_mknull(void)
{
  return mknode(JSON_NULL);
}

JsonNode *json_mkbool(bool b)
{
  JsonNode *ret = mknode(JSON_BOOL);
  ret->bool_ = b;
  return ret;
}

static JsonNode *mkstring(char *s)
{
  JsonNode *ret = mknode(JSON_STRING);
  ret->string_ = s;
  return ret;
}

JsonNode *json_mkstring(const char *s)
{
  return mkstring(json_strdup(s));
}

JsonNode *json_mknumber(double n)
{
  JsonNode *node = mknode(JSON_NUMBER);
  node->number_ = n;
  return node;
}

JsonNode *json_mkarray(void)
{
  return mknode(JSON_ARRAY);
}

JsonNode *json_mkobject(void)
{
  return mknode(JSON_OBJECT);
}

static void append_node(JsonNode *parent, JsonNode *child)
{
  child->parent = parent;
  child->prev = parent->children.tail;
  child->next = NULL;
  
  if (parent->children.tail != NULL)
    parent->children.tail->next = child;
  else
    parent->children.head = child;
  parent->children.tail = child;
}

static void prepend_node(JsonNode *parent, JsonNode *child)
{
  child->parent = parent;
  child->prev = NULL;
  child->next = parent->children.head;
  
  if (parent->children.head != NULL)
    parent->children.head->prev = child;
  else
    parent->children.tail = child;
  parent->children.head = child;
}

static void append_member(JsonNode *object, char *key, JsonNode *value)
{
  value->key = key;
  append_node(object, value);
}

void json_append_element(JsonNode *array, JsonNode *element)
{
  vg_assert(array->tag == JSON_ARRAY);
  vg_assert(element->parent == NULL);
  
  append_node(array, element);
}

void json_prepend_element(JsonNode *array, JsonNode *element)
{
  vg_assert(array->tag == JSON_ARRAY);
  vg_assert(element->parent == NULL);
  
  prepend_node(array, element);
}

void json_append_member(JsonNode *object, const char *key, JsonNode *value)
{
  vg_assert(object->tag == JSON_OBJECT);
  vg_assert(value->parent == NULL);
  
  append_member(object, json_strdup(key), value);
}

void json_prepend_member(JsonNode *object, const char *key, JsonNode *value)
{
  vg_assert(object->tag == JSON_OBJECT);
  vg_assert(value->parent == NULL);
  
  value->key = json_strdup(key);
  prepend_node(object, value);
}

void json_remove_from_parent(JsonNode *node)
{
  JsonNode *parent = node->parent;
  
  if (parent != NULL) {
    if (node->prev != NULL)
      node->prev->next = node->next;
    else
      parent->children.head = node->next;
    if (node->next != NULL)
      node->next->prev = node->prev;
    else
      parent->children.tail = node->prev;
    
    VG_(free)(node->key);
    
    node->parent = NULL;
    node->prev = node->next = NULL;
    node->key = NULL;
  }
}

static bool parse_value(const char **sp, JsonNode **out)
{
  const char *s = *sp;
  
  switch (*s) {
    case 'n':
      if (expect_literal(&s, "null")) {
        if (out)
          *out = json_mknull();
        *sp = s;
        return true;
      }
      return false;
    
    case 'f':
      if (expect_literal(&s, "false")) {
        if (out)
          *out = json_mkbool(false);
        *sp = s;
        return true;
      }
      return false;
    
    case 't':
      if (expect_literal(&s, "true")) {
        if (out)
          *out = json_mkbool(true);
        *sp = s;
        return true;
      }
      return false;
    
    case '"': {
      char *str;
      if (parse_string(&s, out ? &str : NULL)) {
        if (out)
          *out = mkstring(str);
        *sp = s;
        return true;
      }
      return false;
    }
    
    case '[':
      if (parse_array(&s, out)) {
        *sp = s;
        return true;
      }
      return false;
    
    case '{':
      if (parse_object(&s, out)) {
        *sp = s;
        return true;
      }
      return false;
    
    default: {
      double num;
      if (parse_number(&s, out ? &num : NULL)) {
        if (out)
          *out = json_mknumber(num);
        *sp = s;
        return true;
      }
      return false;
    }
  }
}

static bool parse_array(const char **sp, JsonNode **out)
{
  const char *s = *sp;
  JsonNode *ret = out ? json_mkarray() : NULL;
  JsonNode *element;
  
  if (*s++ != '[')
    goto failure;
  skip_space(&s);
  
  if (*s == ']') {
    s++;
    goto success;
  }
  
  for (;;) {
    if (!parse_value(&s, out ? &element : NULL))
      goto failure;
    skip_space(&s);
    
    if (out)
      json_append_element(ret, element);
    
    if (*s == ']') {
      s++;
      goto success;
    }
    
    if (*s++ != ',')
      goto failure;
    skip_space(&s);
  }
  
success:
  *sp = s;
  if (out)
    *out = ret;
  return true;

failure:
  json_delete(ret);
  return false;
}

static bool parse_object(const char **sp, JsonNode **out)
{
  const char *s = *sp;
  JsonNode *ret = out ? json_mkobject() : NULL;
  char *key;
  JsonNode *value;
  
  if (*s++ != '{')
    goto failure;
  skip_space(&s);
  
  if (*s == '}') {
    s++;
    goto success;
  }
  
  for (;;) {
    if (!parse_string(&s, out ? &key : NULL))
      goto failure;
    skip_space(&s);
    
    if (*s++ != ':')
      goto failure_free_key;
    skip_space(&s);
    
    if (!parse_value(&s, out ? &value : NULL))
      goto failure_free_key;
    skip_space(&s);
    
    if (out)
      append_member(ret, key, value);
    
    if (*s == '}') {
      s++;
      goto success;
    }
    
    if (*s++ != ',')
      goto failure;
    skip_space(&s);
  }
  
success:
  *sp = s;
  if (out)
    *out = ret;
  return true;

failure_free_key:
  if (out)
    VG_(free)(key);
failure:
  json_delete(ret);
  return false;
}

bool parse_string(const char **sp, char **out)
{
  const char *s = *sp;
  SB sb;
  char throwaway_buffer[4];
    /* enough space for a UTF-8 character */
  char *b;
  
  if (*s++ != '"')
    return false;
  
  if (out) {
    sb_init(&sb);
    sb_need(&sb, 4);
    b = sb.cur;
  } else {
    b = throwaway_buffer;
  }
  
  while (*s != '"') {
    unsigned char c = *s++;
    
    /* Parse next character, and write it to b. */
    if (c == '\\') {
      c = *s++;
      switch (c) {
        case '"':
        case '\\':
        case '/':
          *b++ = c;
          break;
        case 'b':
          *b++ = '\b';
          break;
        case 'f':
          *b++ = '\f';
          break;
        case 'n':
          *b++ = '\n';
          break;
        case 'r':
          *b++ = '\r';
          break;
        case 't':
          *b++ = '\t';
          break;
        case 'u':
        {
          uint16_t uc, lc;
          uchar_t unicode;
          
          if (!parse_hex16(&s, &uc))
            goto failed;
          
          if (uc >= 0xD800 && uc <= 0xDFFF) {
            /* Handle UTF-16 surrogate pair. */
            if (*s++ != '\\' || *s++ != 'u' || !parse_hex16(&s, &lc))
              goto failed; /* Incomplete surrogate pair. */
            if (!from_surrogate_pair(uc, lc, &unicode))
              goto failed; /* Invalid surrogate pair. */
          } else if (uc == 0) {
            /* Disallow "\u0000". */
            goto failed;
          } else {
            unicode = uc;
          }
          
          b += utf8_write_char(unicode, b);
          break;
        }
        default:
          /* Invalid escape */
          goto failed;
      }
    } else if (c <= 0x1F) {
      /* Control characters are not allowed in string literals. */
      goto failed;
    } else {
      /* Validate and echo a UTF-8 character. */
      int len;
      
      s--;
      len = utf8_validate_cz(s);
      if (len == 0)
        goto failed; /* Invalid UTF-8 character. */
      
      while (len--)
        *b++ = *s++;
    }
    
    /*
     * Update sb to know about the new bytes,
     * and set up b to write another character.
     */
    if (out) {
      sb.cur = b;
      sb_need(&sb, 4);
      b = sb.cur;
    } else {
      b = throwaway_buffer;
    }
  }
  s++;
  
  if (out)
    *out = sb_finish(&sb);
  *sp = s;
  return true;

failed:
  if (out)
    sb_free(&sb);
  return false;
}

/*
 * The JSON spec says that a number shall follow this precise pattern
 * (spaces and quotes added for readability):
 *   '-'? (0 | [1-9][0-9]*) ('.' [0-9]+)? ([Ee] [+-]? [0-9]+)?
 *
 * However, some JSON parsers are more liberal.  For instance, PHP accepts
 * '.5' and '1.'.  JSON.parse accepts '+3'.
 *
 * This function takes the strict approach.
 */
bool parse_number(const char **sp, double *out)
{
  const char *s = *sp;

  /* '-'? */
  if (*s == '-')
    s++;

  /* (0 | [1-9][0-9]*) */
  if (*s == '0') {
    s++;
  } else {
    if (!is_digit(*s))
      return false;
    do {
      s++;
    } while (is_digit(*s));
  }

  /* ('.' [0-9]+)? */
  if (*s == '.') {
    s++;
    if (!is_digit(*s))
      return false;
    do {
      s++;
    } while (is_digit(*s));
  }

  /* ([Ee] [+-]? [0-9]+)? */
  if (*s == 'E' || *s == 'e') {
    s++;
    if (*s == '+' || *s == '-')
      s++;
    if (!is_digit(*s))
      return false;
    do {
      s++;
    } while (is_digit(*s));
  }

  if (out)
    *out = VG_(strtod)(*sp, NULL);

  *sp = s;
  return true;
}

static void skip_space(const char **sp)
{
  const char *s = *sp;
  while (is_space(*s))
    s++;
  *sp = s;
}

static void emit_value(SB *out, const JsonNode *node)
{
  vg_assert(tag_is_valid(node->tag));
  switch (node->tag) {
    case JSON_NULL:
      sb_puts(out, "null");
      break;
    case JSON_BOOL:
      sb_puts(out, node->bool_ ? "true" : "false");
      break;
    case JSON_STRING:
      emit_string(out, node->string_);
      break;
    case JSON_NUMBER:
      emit_number(out, node->number_);
      break;
    case JSON_ARRAY:
      emit_array(out, node);
      break;
    case JSON_OBJECT:
      emit_object(out, node);
      break;
    default:
      vg_assert(false);
  }
}

void emit_value_indented(SB *out, const JsonNode *node, const char *space, int indent_level)
{
  vg_assert(tag_is_valid(node->tag));
  switch (node->tag) {
    case JSON_NULL:
      sb_puts(out, "null");
      break;
    case JSON_BOOL:
      sb_puts(out, node->bool_ ? "true" : "false");
      break;
    case JSON_STRING:
      emit_string(out, node->string_);
      break;
    case JSON_NUMBER:
      emit_number(out, node->number_);
      break;
    case JSON_ARRAY:
      emit_array_indented(out, node, space, indent_level);
      break;
    case JSON_OBJECT:
      emit_object_indented(out, node, space, indent_level);
      break;
    default:
      vg_assert(false);
  }
}

static void emit_array(SB *out, const JsonNode *array)
{
  const JsonNode *element;
  
  sb_putc(out, '[');
  json_foreach(element, array) {
    emit_value(out, element);
    if (element->next != NULL)
      sb_putc(out, ',');
  }
  sb_putc(out, ']');
}

static void emit_array_indented(SB *out, const JsonNode *array, const char *space, int indent_level)
{
  const JsonNode *element = array->children.head;
  int i;
  
  if (element == NULL) {
    sb_puts(out, "[]");
    return;
  }
  
  sb_puts(out, "[\n");
  while (element != NULL) {
    for (i = 0; i < indent_level + 1; i++)
      sb_puts(out, space);
    emit_value_indented(out, element, space, indent_level + 1);
    
    element = element->next;
    sb_puts(out, element != NULL ? ",\n" : "\n");
  }
  for (i = 0; i < indent_level; i++)
    sb_puts(out, space);
  sb_putc(out, ']');
}

static void emit_object(SB *out, const JsonNode *object)
{
  const JsonNode *member;
  
  sb_putc(out, '{');
  json_foreach(member, object) {
    emit_string(out, member->key);
    sb_putc(out, ':');
    emit_value(out, member);
    if (member->next != NULL)
      sb_putc(out, ',');
  }
  sb_putc(out, '}');
}

static void emit_object_indented(SB *out, const JsonNode *object, const char *space, int indent_level)
{
  const JsonNode *member = object->children.head;
  int i;
  
  if (member == NULL) {
    sb_puts(out, "{}");
    return;
  }
  
  sb_puts(out, "{\n");
  while (member != NULL) {
    for (i = 0; i < indent_level + 1; i++)
      sb_puts(out, space);
    emit_string(out, member->key);
    sb_puts(out, ": ");
    emit_value_indented(out, member, space, indent_level + 1);
    
    member = member->next;
    sb_puts(out, member != NULL ? ",\n" : "\n");
  }
  for (i = 0; i < indent_level; i++)
    sb_puts(out, space);
  sb_putc(out, '}');
}

void emit_string(SB *out, const char *str)
{
  bool escape_unicode = false;
  const char *s = str;
  char *b;
  
  vg_assert(utf8_validate(str));
  
  /*
   * 14 bytes is enough space to write up to two
   * \uXXXX escapes and two quotation marks.
   */
  sb_need(out, 14);
  b = out->cur;
  
  *b++ = '"';
  while (*s != 0) {
    unsigned char c = *s++;
    
    /* Encode the next character, and write it to b. */
    switch (c) {
      case '"':
        *b++ = '\\';
        *b++ = '"';
        break;
      case '\\':
        *b++ = '\\';
        *b++ = '\\';
        break;
      case '\b':
        *b++ = '\\';
        *b++ = 'b';
        break;
      case '\f':
        *b++ = '\\';
        *b++ = 'f';
        break;
      case '\n':
        *b++ = '\\';
        *b++ = 'n';
        break;
      case '\r':
        *b++ = '\\';
        *b++ = 'r';
        break;
      case '\t':
        *b++ = '\\';
        *b++ = 't';
        break;
      default: {
        int len;
        
        s--;
        len = utf8_validate_cz(s);
        
        if (len == 0) {
          /*
           * Handle invalid UTF-8 character gracefully in production
           * by writing a replacement character (U+FFFD)
           * and skipping a single byte.
           *
           * This should never happen when assertions are enabled
           * due to the assertion at the beginning of this function.
           */
          vg_assert(false);
          if (escape_unicode) {
            VG_(strcpy)(b, "\\uFFFD");
            b += 6;
          } else {
            *b++ = 0xEF;
            *b++ = 0xBF;
            *b++ = 0xBD;
          }
          s++;
        } else if (c < 0x1F || (c >= 0x80 && escape_unicode)) {
          /* Encode using \u.... */
          uint32_t unicode;
          
          s += utf8_read_char(s, &unicode);
          
          if (unicode <= 0xFFFF) {
            *b++ = '\\';
            *b++ = 'u';
            b += write_hex16(b, unicode);
          } else {
            /* Produce a surrogate pair. */
            uint16_t uc, lc;
            vg_assert(unicode <= 0x10FFFF);
            to_surrogate_pair(unicode, &uc, &lc);
            *b++ = '\\';
            *b++ = 'u';
            b += write_hex16(b, uc);
            *b++ = '\\';
            *b++ = 'u';
            b += write_hex16(b, lc);
          }
        } else {
          /* Write the character directly. */
          while (len--)
            *b++ = *s++;
        }
        
        break;
      }
    }
  
    /*
     * Update *out to know about the new bytes,
     * and set up b to write another encoded character.
     */
    out->cur = b;
    sb_need(out, 14);
    b = out->cur;
  }
  *b++ = '"';
  
  out->cur = b;
}

static void emit_number(SB *out, double num)
{
  /*
   * This isn't exactly how JavaScript renders numbers,
   * but it should produce valid JSON for reasonable numbers
   * preserve precision well enough, and avoid some oddities
   * like 0.3 -> 0.299999999999999988898 .
   */
  char buf[64];
  VG_(sprintf)(buf, "%.16g", num);
  
  if (number_is_valid(buf))
    sb_puts(out, buf);
  else
    sb_puts(out, "null");
}

static bool tag_is_valid(unsigned int tag)
{
  return (/* tag >= JSON_NULL && */ tag <= JSON_OBJECT);
}

static bool number_is_valid(const char *num)
{
  return (parse_number(&num, NULL) && *num == '\0');
}

static bool expect_literal(const char **sp, const char *str)
{
  const char *s = *sp;
  
  while (*str != '\0')
    if (*s++ != *str++)
      return false;
  
  *sp = s;
  return true;
}

/*
 * Parses exactly 4 hex characters (capital or lowercase).
 * Fails if any input chars are not [0-9A-Fa-f].
 */
static bool parse_hex16(const char **sp, uint16_t *out)
{
  const char *s = *sp;
  uint16_t ret = 0;
  uint16_t i;
  uint16_t tmp;
  char c;

  for (i = 0; i < 4; i++) {
    c = *s++;
    if (c >= '0' && c <= '9')
      tmp = c - '0';
    else if (c >= 'A' && c <= 'F')
      tmp = c - 'A' + 10;
    else if (c >= 'a' && c <= 'f')
      tmp = c - 'a' + 10;
    else
      return false;

    ret <<= 4;
    ret += tmp;
  }
  
  if (out)
    *out = ret;
  *sp = s;
  return true;
}

/*
 * Encodes a 16-bit number into hexadecimal,
 * writing exactly 4 hex chars.
 */
static int write_hex16(char *out, uint16_t val)
{
  const char *hex = "0123456789ABCDEF";
  
  *out++ = hex[(val >> 12) & 0xF];
  *out++ = hex[(val >> 8)  & 0xF];
  *out++ = hex[(val >> 4)  & 0xF];
  *out++ = hex[ val        & 0xF];
  
  return 4;
}

bool json_check(const JsonNode *node, char errmsg[256])
{
  #define problem(...) do { \
      if (errmsg != NULL) \
        VG_(snprintf)(errmsg, 256, __VA_ARGS__); \
      return false; \
    } while (0)
  
  if (node->key != NULL && !utf8_validate(node->key))
    problem("key contains invalid UTF-8");
  
  if (!tag_is_valid(node->tag))
    problem("tag is invalid (%u)", node->tag);
  
  if (node->tag == JSON_BOOL) {
    if (node->bool_ != false && node->bool_ != true)
      problem("bool_ is neither false (%d) nor true (%d)", (int)false, (int)true);
  } else if (node->tag == JSON_STRING) {
    if (node->string_ == NULL)
      problem("string_ is NULL");
    if (!utf8_validate(node->string_))
      problem("string_ contains invalid UTF-8");
  } else if (node->tag == JSON_ARRAY || node->tag == JSON_OBJECT) {
    JsonNode *head = node->children.head;
    JsonNode *tail = node->children.tail;
    
    if (head == NULL || tail == NULL) {
      if (head != NULL)
        problem("tail is NULL, but head is not");
      if (tail != NULL)
        problem("head is NULL, but tail is not");
    } else {
      JsonNode *child;
      JsonNode *last = NULL;
      
      if (head->prev != NULL)
        problem("First child's prev pointer is not NULL");
      
      for (child = head; child != NULL; last = child, child = child->next) {
        if (child == node)
          problem("node is its own child");
        if (child->next == child)
          problem("child->next == child (cycle)");
        if (child->next == head)
          problem("child->next == head (cycle)");
        
        if (child->parent != node)
          problem("child does not point back to parent");
        if (child->next != NULL && child->next->prev != child)
          problem("child->next does not point back to child");
        
        if (node->tag == JSON_ARRAY && child->key != NULL)
          problem("Array element's key is not NULL");
        if (node->tag == JSON_OBJECT && child->key == NULL)
          problem("Object member's key is NULL");
        
        if (!json_check(child, errmsg))
          return false;
      }
      
      if (last != tail)
        problem("tail does not match pointer found by starting at head and following next links");
    }
  }
  
  return true;
  
  #undef problem
}

// END json.c


/* Does this TyEnt denote a type, as opposed to some other kind of
   thing? */

Bool ML_(TyEnt__is_type)( const TyEnt* te )
{
   switch (te->tag) {
      case Te_EMPTY: case Te_INDIR: case Te_UNKNOWN: 
      case Te_Atom:  case Te_Field: case Te_Bound:
         return False;
      case Te_TyBase:   case Te_TyPtr:     case Te_TyRef:
      case Te_TyPtrMbr: case Te_TyRvalRef: case Te_TyTyDef:
      case Te_TyStOrUn: case Te_TyEnum:    case Te_TyArray:
      case Te_TyFn:     case Te_TyQual:    case Te_TyVoid:
         return True;
      default:
         vg_assert(0);
   }
}


/* Print a TyEnt, debug-style. */

static void pp_XArray_of_cuOffs ( const XArray* xa )
{
   Word i;
   VG_(printf)("{");
   for (i = 0; i < VG_(sizeXA)(xa); i++) {
      UWord cuOff = *(UWord*)VG_(indexXA)(xa, i);
      VG_(printf)("0x%05lx", cuOff);
      if (i+1 < VG_(sizeXA)(xa))
         VG_(printf)(",");
   }
   VG_(printf)("}");
}

void ML_(pp_TyEnt)( const TyEnt* te )
{
   VG_(printf)("0x%05lx  ", te->cuOff);
   switch (te->tag) {
      case Te_EMPTY:
         VG_(printf)("EMPTY");
         break;
      case Te_INDIR:
         VG_(printf)("INDIR(0x%05lx)", te->Te.INDIR.indR);
         break;
      case Te_UNKNOWN:
         VG_(printf)("UNKNOWN");
         break;
      case Te_Atom:
         VG_(printf)("Te_Atom(%s%lld,\"%s\")",
                     te->Te.Atom.valueKnown ? "" : "unknown:",
                     te->Te.Atom.value, te->Te.Atom.name);
         break;
      case Te_Field:
         if (te->Te.Field.nLoc == -1)
            VG_(printf)("Te_Field(ty=0x%05lx,pos.offset=%ld,\"%s\")",
                        te->Te.Field.typeR, te->Te.Field.pos.offset,
                        te->Te.Field.name ? te->Te.Field.name : "");
         else
            VG_(printf)("Te_Field(ty=0x%05lx,nLoc=%ld,pos.loc=%p,\"%s\")",
                        te->Te.Field.typeR, te->Te.Field.nLoc,
                        te->Te.Field.pos.loc,
                        te->Te.Field.name ? te->Te.Field.name : "");
         break;
      case Te_Bound:
         VG_(printf)("Te_Bound[");
         if (te->Te.Bound.knownL)
            VG_(printf)("%lld", te->Te.Bound.boundL);
         else
            VG_(printf)("??");
         VG_(printf)(",");
         if (te->Te.Bound.knownU)
            VG_(printf)("%lld", te->Te.Bound.boundU);
         else
            VG_(printf)("??");
         VG_(printf)("]");
         break;
      case Te_TyBase:
         VG_(printf)("Te_TyBase(%d,%c,\"%s\")",
                     te->Te.TyBase.szB, te->Te.TyBase.enc,
                     te->Te.TyBase.name ? te->Te.TyBase.name
                                        : "(null)" );
         break;
      case Te_TyPtr:
         VG_(printf)("Te_TyPtr(%d,0x%05lx)", te->Te.TyPorR.szB,
                     te->Te.TyPorR.typeR);
         break;
      case Te_TyRef:
         VG_(printf)("Te_TyRef(%d,0x%05lx)", te->Te.TyPorR.szB,
                     te->Te.TyPorR.typeR);
         break;
      case Te_TyPtrMbr:
         VG_(printf)("Te_TyMbr(%d,0x%05lx)", te->Te.TyPorR.szB,
                     te->Te.TyPorR.typeR);
         break;
      case Te_TyRvalRef:
         VG_(printf)("Te_TyRvalRef(%d,0x%05lx)", te->Te.TyPorR.szB,
                     te->Te.TyPorR.typeR);
         break;
      case Te_TyTyDef:
         VG_(printf)("Te_TyTyDef(0x%05lx,\"%s\")",
                     te->Te.TyTyDef.typeR,
                     te->Te.TyTyDef.name ? te->Te.TyTyDef.name
                                         : "" );
         break;
      case Te_TyStOrUn:
         if (te->Te.TyStOrUn.complete) {
            VG_(printf)("Te_TyStOrUn(%lu,%c,%p,\"%s\")",
                        te->Te.TyStOrUn.szB, 
                        te->Te.TyStOrUn.isStruct ? 'S' : 'U',
                        te->Te.TyStOrUn.fieldRs,
                        te->Te.TyStOrUn.name ? te->Te.TyStOrUn.name
                                             : "" );
            pp_XArray_of_cuOffs( te->Te.TyStOrUn.fieldRs );
         } else {
            VG_(printf)("Te_TyStOrUn(INCOMPLETE,\"%s\")",
                        te->Te.TyStOrUn.name);
         }
         break;
      case Te_TyEnum:
         VG_(printf)("Te_TyEnum(%d,%p,\"%s\")",
                     te->Te.TyEnum.szB, te->Te.TyEnum.atomRs,
                     te->Te.TyEnum.name ? te->Te.TyEnum.name
                                        : "" );
         if (te->Te.TyEnum.atomRs)
            pp_XArray_of_cuOffs( te->Te.TyEnum.atomRs );
         break;
      case Te_TyArray:
         VG_(printf)("Te_TyArray(0x%05lx,%p)",
                     te->Te.TyArray.typeR, te->Te.TyArray.boundRs);
         if (te->Te.TyArray.boundRs)
            pp_XArray_of_cuOffs( te->Te.TyArray.boundRs );
         break;
      case Te_TyFn:
         VG_(printf)("Te_TyFn");
         break;
      case Te_TyQual:
         VG_(printf)("Te_TyQual(%c,0x%05lx)", te->Te.TyQual.qual,
                     te->Te.TyQual.typeR);
         break;
      case Te_TyVoid:
         VG_(printf)("Te_TyVoid%s",
                     te->Te.TyVoid.isFake ? "(fake)" : "");
         break;
      default:
         vg_assert(0);
   }
}


/* Print a whole XArray of TyEnts, debug-style */

void ML_(pp_TyEnts)( const XArray* tyents, const HChar* who )
{
   Word i, n;
   VG_(printf)("------ %s ------\n", who);
   n = VG_(sizeXA)( tyents );
   for (i = 0; i < n; i++) {
      const TyEnt* tyent = VG_(indexXA)( tyents, i );
      VG_(printf)("   [%5ld]  ", i);
      ML_(pp_TyEnt)( tyent );
      VG_(printf)("\n");
   }
}


/* Print a TyEnt, C style, chasing stuff as necessary. */

static void pp_TyBound_C_ishly ( const XArray* tyents, UWord cuOff )
{
   TyEnt* ent = ML_(TyEnts__index_by_cuOff)( tyents, NULL, cuOff );
   if (!ent) {
      VG_(printf)("**bounds-have-invalid-cuOff**");
      return;
   }
   vg_assert(ent->tag == Te_Bound);
   if (ent->Te.Bound.knownL && ent->Te.Bound.knownU
       && ent->Te.Bound.boundL == 0) {
      VG_(printf)("[%lld]", 1 + ent->Te.Bound.boundU);
   }
   else
   if (ent->Te.Bound.knownL && (!ent->Te.Bound.knownU) 
       && ent->Te.Bound.boundL == 0) {
      VG_(printf)("[]");
   }
   else
      ML_(pp_TyEnt)( ent );
}

void ML_(pp_TyEnt_C_ishly)( const XArray* /* of TyEnt */ tyents,
                            UWord cuOff )
{
   TyEnt* ent = ML_(TyEnts__index_by_cuOff)( tyents, NULL, cuOff );
   if (!ent) {
      VG_(printf)("**type-has-invalid-cuOff**");
      return;
   }
   switch (ent->tag) {
      case Te_TyBase:
         if (!ent->Te.TyBase.name) goto unhandled;
         VG_(printf)("%s", ent->Te.TyBase.name);
         break;
      case Te_TyPtr:
         ML_(pp_TyEnt_C_ishly)(tyents, ent->Te.TyPorR.typeR);
         VG_(printf)("*");
         break;
      case Te_TyRef:
         ML_(pp_TyEnt_C_ishly)(tyents, ent->Te.TyPorR.typeR);
         VG_(printf)("&");
         break;
      case Te_TyPtrMbr:
         ML_(pp_TyEnt_C_ishly)(tyents, ent->Te.TyPorR.typeR);
         VG_(printf)("*");
         break;
      case Te_TyRvalRef:
         ML_(pp_TyEnt_C_ishly)(tyents, ent->Te.TyPorR.typeR);
         VG_(printf)("&&");
         break;
      case Te_TyEnum:
         VG_(printf)("enum %s", ent->Te.TyEnum.name ? ent->Te.TyEnum.name
                                                    : "<anonymous>" );
         break;
      case Te_TyStOrUn:
         VG_(printf)("%s %s",
                     ent->Te.TyStOrUn.isStruct ? "struct" : "union",
                     ent->Te.TyStOrUn.name ? ent->Te.TyStOrUn.name
                                           : "<anonymous>" );
         break;
      case Te_TyArray:
         ML_(pp_TyEnt_C_ishly)(tyents, ent->Te.TyArray.typeR);
         if (ent->Te.TyArray.boundRs) {
            Word    w;
            XArray* xa = ent->Te.TyArray.boundRs;
            for (w = 0; w < VG_(sizeXA)(xa); w++) {
               pp_TyBound_C_ishly( tyents, *(UWord*)VG_(indexXA)(xa, w) );
            }
         } else {
            VG_(printf)("%s", "[??]");
         }
         break;
      case Te_TyTyDef:
         VG_(printf)("%s", ent->Te.TyTyDef.name ? ent->Te.TyTyDef.name
                                                : "<anonymous>" );
         break;
      case Te_TyFn:
         VG_(printf)("%s", "<function_type>");
         break;
      case Te_TyQual:
         switch (ent->Te.TyQual.qual) {
            case 'C': VG_(printf)("const "); break;
            case 'V': VG_(printf)("volatile "); break;
            case 'R': VG_(printf)("restrict "); break;
            default: goto unhandled;
         }
         ML_(pp_TyEnt_C_ishly)(tyents, ent->Te.TyQual.typeR);
         break;
      case Te_TyVoid:
         VG_(printf)("%svoid",
                     ent->Te.TyVoid.isFake ? "fake" : "");
         break;
      case Te_UNKNOWN:
         ML_(pp_TyEnt)(ent);
         break;
      default:
         goto unhandled;
   }
   return;

  unhandled:
   VG_(printf)("pp_TyEnt_C_ishly:unhandled: ");
   ML_(pp_TyEnt)(ent);
   vg_assert(0);
}


// pgbovine version of pp_TyBound_C_ishly
/*
static void pg_pp_TyBound( const XArray* tyents, UWord cuOff )
{
   TyEnt* ent = ML_(TyEnts__index_by_cuOff)( tyents, NULL, cuOff );
   if (!ent) {
      VG_(printf)("**bounds-have-invalid-cuOff**");
      return;
   }
   vg_assert(ent->tag == Te_Bound);
   if (ent->Te.Bound.knownL && ent->Te.Bound.knownU
       && ent->Te.Bound.boundL == 0) {
      VG_(printf)("[%lld]", 1 + ent->Te.Bound.boundU);
   }
   else
   if (ent->Te.Bound.knownL && (!ent->Te.Bound.knownU) 
       && ent->Te.Bound.boundL == 0) {
      VG_(printf)("[]");
   }
   else
      ML_(pp_TyEnt)( ent );
}
*/

SizeT pg_get_elt_size(TyEnt* ent);
SizeT pg_get_elt_size(TyEnt* ent)
{
  switch (ent->tag) {
    case Te_TyBase:
      return ent->Te.TyBase.szB;
    case Te_TyPtr:
    case Te_TyRef:
      return ent->Te.TyPorR.szB;
    case Te_TyEnum:
      return ent->Te.TyEnum.szB;
    case Te_TyStOrUn:
      return ent->Te.TyStOrUn.szB;

    // TODO: handle these in the future
    case Te_EMPTY:
    case Te_INDIR:
    case Te_UNKNOWN:
    case Te_Atom:
    case Te_Field:
    case Te_Bound:
    case Te_TyPtrMbr:
    case Te_TyRvalRef:
    case Te_TyTyDef:
    case Te_TyArray:
    case Te_TyFn:
    case Te_TyQual:
    case Te_TyVoid:
      vg_assert(0); // unhandled
  }
  vg_assert(0); // unhandled
}


// pgbovine version of ML_(pp_TyEnt_C_ishly)
void ML_(pg_pp_varinfo)( const XArray* /* of TyEnt */ tyents,
                         UWord cuOff,
                         Addr data_addr,
                         int is_mem_defined_func(Addr, SizeT, Addr*, UInt*),
                         OSet* encoded_addrs)
{
   TyEnt* ent = ML_(TyEnts__index_by_cuOff)( tyents, NULL, cuOff );
   if (!ent) {
      VG_(printf)("**type-has-invalid-cuOff**");
      return;
   }

   Addr bad_addr;
   UInt otag = 0;
   int res;

   switch (ent->tag) {
      case Te_TyBase:
         if (!ent->Te.TyBase.name) goto unhandled;

         // check whether this memory has been allocated and/or initialized
         res = is_mem_defined_func(data_addr, ent->Te.TyBase.szB,
                                       &bad_addr, &otag);
         if (res == 6 /* MC_AddrErr enum value */) {
           VG_(printf)("  UNALLOC");
           return; // early!
         } else if (res == 7 /* MC_ValueErr enum value */) {
           VG_(printf)("  UNINIT");
           return; // early!
         } else {
           tl_assert(res == 5 /* MC_Ok enum value */);
           // record that this block has been rendered
           if (!VG_(OSetWord_Contains)(encoded_addrs, (UWord)data_addr)) {
             VG_(OSetWord_Insert)(encoded_addrs, (UWord)data_addr);
           }
         }

         // attempt to print out the value
         VG_(printf)("[base] %s(%d%c)",
                     ent->Te.TyBase.name,
                     ent->Te.TyBase.szB,
                     ent->Te.TyBase.enc);

         if (ent->Te.TyBase.enc == 'S') {
           if (ent->Te.TyBase.szB == sizeof(char)) {
             char val = *((char*)data_addr);
             // special-case printing
             if (val == '\0') {
               VG_(printf)(" val=\\0");
             } else {
               VG_(printf)(" val=%c", val);
             }
           } else if (ent->Te.TyBase.szB == sizeof(short)) {
             VG_(printf)(" val=%d", *((short*)data_addr));
           } else if (ent->Te.TyBase.szB == sizeof(int)) {
             VG_(printf)(" val=%d", *((int*)data_addr));
           } else if (ent->Te.TyBase.szB == sizeof(long int)) {
             VG_(printf)(" val=%ld", *((long int*)data_addr));
           } else {
             // what other stuff is here?!?
             vg_assert(0);
           }
         } else if (ent->Te.TyBase.enc == 'U') {
           if (ent->Te.TyBase.szB == sizeof(unsigned char)) {
             // TODO: print as number or character?
             VG_(printf)(" val=%u", *((unsigned char*)data_addr));
           } else if (ent->Te.TyBase.szB == sizeof(unsigned short)) {
             VG_(printf)(" val=%u", *((unsigned short*)data_addr));
           } else if (ent->Te.TyBase.szB == sizeof(unsigned int)) {
             VG_(printf)(" val=%u", *((unsigned int*)data_addr));
           } else if (ent->Te.TyBase.szB == sizeof(unsigned long int)) {
             VG_(printf)(" val=%lu", *((unsigned long int*)data_addr));
           } else {
             // what other stuff is here?!?
             vg_assert(0);
           }
         } else if (ent->Te.TyBase.enc == 'F') {
           // careful about subtleties around floats and doubles and stuff ..
           if (ent->Te.TyBase.szB == sizeof(float)) {
             VG_(printf)(" val=%f", *((float*)data_addr));
           } else if (ent->Te.TyBase.szB == sizeof(double)) {
             VG_(printf)(" val=%f", *((double*)data_addr));
           } else if (ent->Te.TyBase.szB == sizeof(long double)) {
             // TODO: doesn't currently work for some reason :(
             // long doubles are shown as uninit
             VG_(printf)(" val=%Lf", *((long double*)data_addr));
           } else {
             // what other stuff is here?!?
             vg_assert(0);
           }
         } else if (ent->Te.TyBase.enc == 'C') {
           // complex floats are unhandled right now
           vg_assert(0); // unhandled
         } else {
           vg_assert(0); // are there any cases left?
         }

         break;
      case Te_TyPtr:
         VG_(printf)("[ptr] ");

         // check whether this memory has been allocated and/or initialized
         res = is_mem_defined_func(data_addr, ent->Te.TyPorR.szB,
                                   &bad_addr, &otag);
         if (res == 6 /* MC_AddrErr enum value */) {
           VG_(printf)(" UNALLOC");
           return; // early!
         } else if (res == 7 /* MC_ValueErr enum value */) {
           VG_(printf)(" UNINIT");
           return; // early!
         } else {
           tl_assert(res == 5 /* MC_Ok enum value */);
           // record that this block has been rendered
           if (!VG_(OSetWord_Contains)(encoded_addrs, (UWord)data_addr)) {
             VG_(OSetWord_Insert)(encoded_addrs, (UWord)data_addr);
           }
         }

         // ok so now we know data_addr is legit, so we can dereference
         // it to get its value
         Addr ptr_val = *((Addr*)data_addr);

         // what do we do now? ptr_val is either a pointer:
         // - that's invalid (e.g., null, garbage)
         // - to the stack
         // - to the global area
         // - to the heap
         //
         // if it's a pointer to the stack or global area, then if that
         // variable is in scope, then it will already be printed out
         // elsewhere, so we just need to print the pointer value so
         // that the visualization knows to draw an arrow to there.
         //
         // if it's a pointer to the heap AND this heap object hasn't
         // yet been traversed (to be visualized), then we need to go in
         // and traverse it so that we can visualize it. then we also
         // need to print the pointer value so that the visualization
         // knows to draw an arrow to there.

         AddrInfo ai;
         VG_(describe_addr)(ptr_val, &ai);
         if (ai.tag == Addr_Block) {
           // if this is a heap pointer ...

           TyEnt* element_ent = ML_(TyEnts__index_by_cuOff)(tyents, NULL, ent->Te.TyPorR.typeR);
           SizeT element_size = pg_get_elt_size(element_ent);

           Addr block_base_addr = ptr_val - ai.Addr.Block.rwoffset;
           VG_(printf)("<heap ptr %p, sz: %d, base: %p, off: %d, eltsize: %d>",
                       (void*)ptr_val,
                       (int)ai.Addr.Block.block_szB /* total block size in bytes; doesn't mean
                                                       all has been allocated by malloc, tho */,
                       (void*)block_base_addr,
                       (int)ai.Addr.Block.rwoffset /* offset in bytes */,
                       (int)element_size);

           vg_assert(encoded_addrs);

           // avoid rendering duplicates, to prevent redundancies and infinite loops
           if (!VG_(OSetWord_Contains)(encoded_addrs,
                                       (UWord)block_base_addr)) {
             VG_(OSetWord_Insert)(encoded_addrs,
                                  (UWord)block_base_addr);

             // scan until we find first UNALLOC address, and use that as
             // the upper bound of the heap array
             // TODO: any risk of overrun into other blocks? hopefully
             // not, due to redzones
             Addr cur_addr = block_base_addr;
             while (1) {
               res = is_mem_defined_func(cur_addr, element_size,
                                         &bad_addr, &otag);
               if (res == 6 /* MC_AddrErr enum value */) {
                 VG_(printf)("\n  UNALLOC");
                 break; // break on first unallocated byte
               } else if (res == 7 /* MC_ValueErr enum value */) {
                 VG_(printf)("\n  UNINIT");
               } else {
                 tl_assert(res == 5 /* MC_Ok enum value */);
                 VG_(printf)("\n  elt: ");
                 // recurse!
                 ML_(pg_pp_varinfo)(tyents, ent->Te.TyPorR.typeR, cur_addr,
                                    is_mem_defined_func, encoded_addrs);
               }

               cur_addr += element_size;
             }
           } else {
             VG_(printf)("heap pointer already encoded!\n");
           }
         } else if (ai.tag == Addr_SegmentKind) {
           // this is a pointer to some global client area, i think
           //
           // there aren't any redzones, so use heuristics to figure
           // out what to print out here. the most common is a string
           // literal like "hello world", so in that case, just end
           // at the null terminator.
           VG_(printf)("<client segment ptr %p, tag: %d R:%d, W:%d, X:%d>", (void*)ptr_val,
                       (int)ai.tag,
                       (int)ai.Addr.SegmentKind.hasR,
                       (int)ai.Addr.SegmentKind.hasW,
                       (int)ai.Addr.SegmentKind.hasX);

           // avoid rendering duplicates, to prevent redundancies and infinite loops
           if (!VG_(OSetWord_Contains)(encoded_addrs,
                                       (UWord)ptr_val)) {
             VG_(OSetWord_Insert)(encoded_addrs, (UWord)ptr_val);

             TyEnt* element_ent = ML_(TyEnts__index_by_cuOff)(tyents, NULL, ent->Te.TyPorR.typeR);
             SizeT element_size = pg_get_elt_size(element_ent);

             // only try to print out string literals like "hello world"
             if (element_ent->tag == Te_TyBase &&
                 element_ent->Te.TyBase.enc == 'S' &&
                 element_ent->Te.TyBase.szB == sizeof(char)) {
               Addr cur_addr = ptr_val;
               while (1) {
                 res = is_mem_defined_func(cur_addr, element_size,
                                           &bad_addr, &otag);
                 if (res == 6 /* MC_AddrErr enum value */) {
                   VG_(printf)("\n  UNALLOC");
                   break; // break on first unallocated byte
                 } else if (res == 7 /* MC_ValueErr enum value */) {
                   VG_(printf)("\n  UNINIT");
                 } else {
                   tl_assert(res == 5 /* MC_Ok enum value */);
                   VG_(printf)("\n  elt: ");
                   // recurse!
                   ML_(pg_pp_varinfo)(tyents, ent->Te.TyPorR.typeR, cur_addr,
                                      is_mem_defined_func, encoded_addrs);

                   // if it's a '\0' character, then BREAK out of the
                   // loop since that terminates the string
                   if (*((char*)cur_addr) == '\0') {
                     break;
                   }
                 }
                 cur_addr += element_size;
               }
             }
           }
         } else {
           VG_(printf)("<other ptr %p, tag: %d>", (void*)ptr_val, (int)ai.tag);
         }
         break;
      case Te_TyRef:
         vg_assert(0); // unhandled
         ML_(pg_pp_varinfo)(tyents, ent->Te.TyPorR.typeR, data_addr /* stent */,
                            is_mem_defined_func, encoded_addrs);
         VG_(printf)("&");
         break;
      case Te_TyPtrMbr:
         vg_assert(0); // unhandled
         ML_(pg_pp_varinfo)(tyents, ent->Te.TyPorR.typeR, data_addr /* stent */,
                            is_mem_defined_func, encoded_addrs);
         VG_(printf)("*");
         break;
      case Te_TyRvalRef:
         vg_assert(0); // unhandled
         ML_(pg_pp_varinfo)(tyents, ent->Te.TyPorR.typeR, data_addr /* stent */,
                            is_mem_defined_func, encoded_addrs);
         VG_(printf)("&&");
         break;
      case Te_TyEnum:
         vg_assert(0); // unhandled
         VG_(printf)("enum %s", ent->Te.TyEnum.name ? ent->Te.TyEnum.name
                                                    : "<anonymous>" );
         break;
      case Te_TyStOrUn:
         VG_(printf)("%s %s",
                     ent->Te.TyStOrUn.isStruct ? "struct" : "union",
                     ent->Te.TyStOrUn.name ? ent->Te.TyStOrUn.name
                                           : "<anonymous>" );
         // TODO: handle unions later, let's just focus on structs for now
         vg_assert(ent->Te.TyStOrUn.isStruct);

         // iterate into ent->Te.TyStOrUn.fieldRs to print all fields
         XArray* fieldRs = ent->Te.TyStOrUn.fieldRs;

         // adapted from describe_type()
         for (int i = 0; i < VG_(sizeXA)( fieldRs ); i++) {
           UWord fieldR = *(UWord*)VG_(indexXA)( fieldRs, i );
           TyEnt* field = ML_(TyEnts__index_by_cuOff)(tyents, NULL, fieldR);
           vg_assert(field && field->tag == Te_Field);

           // TODO: handle unions later, let's just focus on structs for now
           vg_assert(field->Te.Field.isStruct);
           // TODO: how should we handle nLoc >= 0?
           vg_assert(field->Te.Field.nLoc == -1);

           Addr field_base_addr = data_addr + field->Te.Field.pos.offset;
           VG_(printf)("\nFIELD %s offset: %d\n  ",
                       field->Te.Field.name,
                       (int)field->Te.Field.pos.offset);

           // recurse!
           ML_(pg_pp_varinfo)(tyents, field->Te.Field.typeR, field_base_addr,
                              is_mem_defined_func, encoded_addrs);
         }

         break;
      case Te_TyArray:
         if (ent->Te.TyArray.boundRs) {
            // an array with a known size, yay!
            VG_(printf)("[array %p] ", (void*)data_addr);

            XArray* xa = ent->Te.TyArray.boundRs;
            // TODO: handle multi-dimensional arrays; right now we handle only 1-D
            // for simplicity
            vg_assert(VG_(sizeXA)(xa) == 1);
            UWord bound_cuOff = *(UWord*)VG_(indexXA)(xa, 0);

            // the type entry of the array element(s)
            TyEnt* element_ent = ML_(TyEnts__index_by_cuOff)(tyents, NULL, ent->Te.TyArray.typeR);
            SizeT element_size = pg_get_elt_size(element_ent);

            // inlined from pg_pp_TyBound
            TyEnt* bound_ent = ML_(TyEnts__index_by_cuOff)( tyents, NULL, bound_cuOff );
            vg_assert(bound_ent && bound_ent->tag == Te_Bound);
            if (bound_ent->Te.Bound.knownL && bound_ent->Te.Bound.knownU
                && bound_ent->Te.Bound.boundL == 0) {
              // yay, an array with known bounds!

              Addr cur_elt_addr = data_addr;
              for (Long i = 0; i <= bound_ent->Te.Bound.boundU /* inclusive */; i++) {
                VG_(printf)("\n    ");
                ML_(pg_pp_varinfo)(tyents, ent->Te.TyArray.typeR, cur_elt_addr,
                                   is_mem_defined_func, encoded_addrs);
                cur_elt_addr += element_size;
              }
            }
            else if (bound_ent->Te.Bound.knownL && (!bound_ent->Te.Bound.knownU)
                && bound_ent->Te.Bound.boundL == 0) {
              vg_assert(0); // unhandled - unknown bounds. TODO: maybe treat like a pointer?
              VG_(printf)("[]");
            }
            else {
              vg_assert(0); // unhandled // no bounds!
            }

            // original multi-dimensional traversal code
            /*
            for (w = 0; w < VG_(sizeXA)(xa); w++) {
               pg_pp_TyBound( tyents, *(UWord*)VG_(indexXA)(xa, w) );
            }
            */
         } else {
            vg_assert(0); // unhandled // no bounds!
            VG_(printf)("%s", "[??]");
         }
         break;
      case Te_TyTyDef:
         // typedef -- directly recurse into the typeR field
         VG_(printf)("typedef %s\n", ent->Te.TyTyDef.name ? ent->Te.TyTyDef.name : "<anonymous>" );
         ML_(pg_pp_varinfo)(tyents, ent->Te.TyTyDef.typeR, data_addr,
                            is_mem_defined_func, encoded_addrs);
         break;
      case Te_TyFn:
         vg_assert(0); // unhandled
         VG_(printf)("%s", "<function_type>");
         break;
      case Te_TyQual:
         // PG - ignore qualifiers and traverse inward!
         /*
         switch (ent->Te.TyQual.qual) {
            case 'C': VG_(printf)("const "); break;
            case 'V': VG_(printf)("volatile "); break;
            case 'R': VG_(printf)("restrict "); break;
            default: goto unhandled;
         }
         */
         ML_(pg_pp_varinfo)(tyents, ent->Te.TyQual.typeR, data_addr,
                            is_mem_defined_func, encoded_addrs);
         break;
      case Te_TyVoid:
         vg_assert(0); // unhandled
         VG_(printf)("%svoid",
                     ent->Te.TyVoid.isFake ? "fake" : "");
         break;
      case Te_UNKNOWN:
         vg_assert(0); // unhandled
         ML_(pp_TyEnt)(ent);
         break;
      default:
         goto unhandled;
   }
   return;

  unhandled:
   VG_(printf)("pg_pp_varinfo:unhandled: ");
   ML_(pp_TyEnt)(ent);
   vg_assert(0);
}


/* 'ents' is an XArray of TyEnts, sorted by their .cuOff fields.  Find
   the entry which has .cuOff field as specified.  Returns NULL if not
   found.  Asserts if more than one entry has the specified .cuOff
   value. */

void ML_(TyEntIndexCache__invalidate) ( TyEntIndexCache* cache )
{
   Word i;
   for (i = 0; i < N_TYENT_INDEX_CACHE; i++) {
      cache->ce[i].cuOff0 = 0;    /* not actually necessary */
      cache->ce[i].ent0   = NULL; /* "invalid entry" */
      cache->ce[i].cuOff1 = 0;    /* not actually necessary */
      cache->ce[i].ent1   = NULL; /* "invalid entry" */
   }
}

TyEnt* ML_(TyEnts__index_by_cuOff) ( const XArray* /* of TyEnt */ ents,
                                     TyEntIndexCache* cache,
                                     UWord cuOff_to_find )
{
   Bool  found;
   Word  first, last;
   TyEnt key, *res;

   /* crude stats, aggregated over all caches */
   static UWord cacheQs = 0 - 1;
   static UWord cacheHits = 0;

   if (0 && 0 == (cacheQs & 0xFFFF))
      VG_(printf)("cache: %'lu queries, %'lu misses\n", 
                  cacheQs, cacheQs - cacheHits);

   if (LIKELY(cache != NULL)) {
      UWord h = cuOff_to_find % (UWord)N_TYENT_INDEX_CACHE;
      cacheQs++;
      // dude, like, way 0, dude.
      if (cache->ce[h].cuOff0 == cuOff_to_find && cache->ce[h].ent0 != NULL) {
         // dude, way 0 is a total hit!
         cacheHits++;
         return cache->ce[h].ent0;
      }
      // dude, check out way 1, dude.
      if (cache->ce[h].cuOff1 == cuOff_to_find && cache->ce[h].ent1 != NULL) {
         // way 1 hit
         UWord  tc;
         TyEnt* te;
         cacheHits++;
         // dude, way 1 is the new way 0.  move with the times, dude.
         tc = cache->ce[h].cuOff0;
         te = cache->ce[h].ent0;
         cache->ce[h].cuOff0 = cache->ce[h].cuOff1;
         cache->ce[h].ent0   = cache->ce[h].ent1;
         cache->ce[h].cuOff1 = tc;
         cache->ce[h].ent1   = te;
         return cache->ce[h].ent0;
      }
   }

   /* We'll have to do it the hard way */
   key.cuOff = cuOff_to_find;
   key.tag   = Te_EMPTY;
   found = VG_(lookupXA)( ents, &key, &first, &last );
   //found = VG_(lookupXA_UNBOXED)( ents, cuOff_to_find, &first, &last, 
   //                               offsetof(TyEnt,cuOff) );
   if (!found)
      return NULL;
   /* If this fails, the array is invalid in the sense that there is
      more than one entry with .cuOff == cuOff_to_find. */
   vg_assert(first == last);
   res = (TyEnt*)VG_(indexXA)( ents, first );

   if (LIKELY(cache != NULL) && LIKELY(res != NULL)) {
      /* this is a bit stupid, computing this twice.  Oh well.
         Perhaps some magic gcc transformation will common them up.
         re "res != NULL", since .ent of NULL denotes 'invalid entry',
         we can't cache the result when res == NULL. */
      UWord h = cuOff_to_find % (UWord)N_TYENT_INDEX_CACHE;
      cache->ce[h].cuOff1 = cache->ce[h].cuOff0;
      cache->ce[h].ent1   = cache->ce[h].ent0;
      cache->ce[h].cuOff0 = cuOff_to_find;
      cache->ce[h].ent0   = res;
   }

   return res;
}


/* Generates a total ordering on TyEnts based only on their .cuOff
   fields. */

Word ML_(TyEnt__cmp_by_cuOff_only) ( const TyEnt* te1, const TyEnt* te2 )
{
   if (te1->cuOff < te2->cuOff) return -1;
   if (te1->cuOff > te2->cuOff) return 1;
   return 0;
}


/* Generates a total ordering on TyEnts based on everything except
   their .cuOff fields. */
static inline Word UWord__cmp ( UWord a, UWord b ) {
   if (a < b) return -1;
   if (a > b) return 1;
   return 0;
}
static inline Word Long__cmp ( Long a, Long b ) {
   if (a < b) return -1;
   if (a > b) return 1;
   return 0;
}
static inline Word Bool__cmp ( Bool a, Bool b ) {
   vg_assert( ((UWord)a) <= 1 );
   vg_assert( ((UWord)b) <= 1 );
   if (a < b) return -1;
   if (a > b) return 1;
   return 0;
}
static inline Word UChar__cmp ( UChar a, UChar b ) {
   if (a < b) return -1;
   if (a > b) return 1;
   return 0;
}
static inline Word Int__cmp ( Int a, Int b ) {
   if (a < b) return -1;
   if (a > b) return 1;
   return 0;
}
static Word XArray_of_UWord__cmp ( const XArray* a, const XArray* b ) {
   Word i, r;
   Word aN = VG_(sizeXA)( a );
   Word bN = VG_(sizeXA)( b );
   if (aN < bN) return -1;
   if (aN > bN) return 1;
   for (i = 0; i < aN; i++) {
      r = UWord__cmp( *(UWord*)VG_(indexXA)( a, i ),
                      *(UWord*)VG_(indexXA)( b, i ) );
      if (r != 0) return r;
   }
   return 0;
}
static Word Bytevector__cmp ( const UChar* a, const UChar* b, Word n ) {
   Word i, r;
   vg_assert(n >= 0);
   for (i = 0; i < n; i++) {
      r = UChar__cmp( a[i], b[i] );
      if (r != 0) return r;
   }
   return 0;
}
static Word Asciiz__cmp ( const HChar* a, const HChar* b ) {
   /* A wrapper around strcmp that handles NULL strings safely. */
   if (a == NULL && b == NULL) return 0;
   if (a == NULL && b != NULL) return -1;
   if (a != NULL && b == NULL) return 1;
   return VG_(strcmp)(a, b);
}

Word ML_(TyEnt__cmp_by_all_except_cuOff) ( const TyEnt* te1, const TyEnt* te2 )
{
   Word r;
   if (te1->tag < te2->tag) return -1;
   if (te1->tag > te2->tag) return 1;
   switch (te1->tag) {
   case Te_EMPTY:
      return 0;
   case Te_INDIR:
      r = UWord__cmp(te1->Te.INDIR.indR, te2->Te.INDIR.indR);
      return r;
   case Te_Atom:
      r = Bool__cmp(te1->Te.Atom.valueKnown, te2->Te.Atom.valueKnown);
      if (r != 0) return r;
      r = Long__cmp(te1->Te.Atom.value, te2->Te.Atom.value);
      if (r != 0) return r;
      r = Asciiz__cmp(te1->Te.Atom.name, te2->Te.Atom.name);
      return r;
   case Te_Field:
      r = Bool__cmp(te1->Te.Field.isStruct, te2->Te.Field.isStruct);
      if (r != 0) return r;
      r = UWord__cmp(te1->Te.Field.typeR, te2->Te.Field.typeR);
      if (r != 0) return r;
      r = Asciiz__cmp(te1->Te.Field.name, te2->Te.Field.name);
      if (r != 0) return r;
      r = UWord__cmp(te1->Te.Field.nLoc, te2->Te.Field.nLoc);
      if (r != 0) return r;
      if (te1->Te.Field.nLoc == -1)
         r = Long__cmp(te1->Te.Field.pos.offset, te2->Te.Field.pos.offset);
      else
         r = Bytevector__cmp(te1->Te.Field.pos.loc, te2->Te.Field.pos.loc,
                             te1->Te.Field.nLoc);
      return r;
   case Te_Bound:
      r = Bool__cmp(te1->Te.Bound.knownL, te2->Te.Bound.knownL);
      if (r != 0) return r;
      r = Bool__cmp(te1->Te.Bound.knownU, te2->Te.Bound.knownU);
      if (r != 0) return r;
      r = Long__cmp(te1->Te.Bound.boundL, te2->Te.Bound.boundL);
      if (r != 0) return r;
      r = Long__cmp(te1->Te.Bound.boundU, te2->Te.Bound.boundU);
      return r;
   case Te_TyBase:
      r = UChar__cmp(te1->Te.TyBase.enc, te2->Te.TyBase.enc);
      if (r != 0) return r;
      r = Int__cmp(te1->Te.TyBase.szB, te2->Te.TyBase.szB);
      if (r != 0) return r;
      r = Asciiz__cmp(te1->Te.TyBase.name, te2->Te.TyBase.name);
      return r;
   case Te_TyPtr:
   case Te_TyRef:
   case Te_TyPtrMbr:
   case Te_TyRvalRef:
      r = Int__cmp(te1->Te.TyPorR.szB, te2->Te.TyPorR.szB);
      if (r != 0) return r;
      r = UWord__cmp(te1->Te.TyPorR.typeR, te2->Te.TyPorR.typeR);
      return r;
   case Te_TyTyDef:
      r = UWord__cmp(te1->Te.TyTyDef.typeR, te2->Te.TyTyDef.typeR);
      if (r != 0) return r;
      r = Asciiz__cmp(te1->Te.TyTyDef.name, te2->Te.TyTyDef.name);
      return r;
   case Te_TyStOrUn:
      r = Bool__cmp(te1->Te.TyStOrUn.isStruct, te2->Te.TyStOrUn.isStruct);
      if (r != 0) return r;
      r = Bool__cmp(te1->Te.TyStOrUn.complete, te2->Te.TyStOrUn.complete);
      if (r != 0) return r;
      r = UWord__cmp(te1->Te.TyStOrUn.szB, te2->Te.TyStOrUn.szB);
      if (r != 0) return r;
      r = Asciiz__cmp(te1->Te.TyStOrUn.name, te2->Te.TyStOrUn.name);
      if (r != 0) return r;
      r = XArray_of_UWord__cmp(te1->Te.TyStOrUn.fieldRs,
                               te2->Te.TyStOrUn.fieldRs);
      return r;
   case Te_TyEnum:
      r = Int__cmp(te1->Te.TyEnum.szB, te2->Te.TyEnum.szB);
      if (r != 0) return r;
      r = Asciiz__cmp(te1->Te.TyEnum.name, te2->Te.TyEnum.name);
      if (r != 0) return r;
      r = XArray_of_UWord__cmp(te1->Te.TyEnum.atomRs, te2->Te.TyEnum.atomRs);
      return r;
   case Te_TyArray:
      r = UWord__cmp(te1->Te.TyArray.typeR, te2->Te.TyArray.typeR);
      if (r != 0) return r;
      r = XArray_of_UWord__cmp(te1->Te.TyArray.boundRs,
                               te2->Te.TyArray.boundRs);
      return r;
   case Te_TyFn:
      return 0;
   case Te_TyQual:
      r = UWord__cmp(te1->Te.TyQual.typeR, te2->Te.TyQual.typeR);
      if (r != 0) return r;
      r = UChar__cmp(te1->Te.TyQual.qual, te2->Te.TyQual.qual);
      return r;
   case Te_TyVoid:
      r = Bool__cmp(te1->Te.TyVoid.isFake, te2->Te.TyVoid.isFake);
      return r;
   default:
      vg_assert(0);
   }
}


/* Free up all directly or indirectly heap-allocated stuff attached to
   this TyEnt, and set its tag to Te_EMPTY.  The .cuOff field is
   unchanged. */

void ML_(TyEnt__make_EMPTY) ( TyEnt* te )
{
   UWord saved_cuOff;
   /* First, free up any fields in mallocville. */
   switch (te->tag) {
      case Te_EMPTY:
         break;
      case Te_INDIR:
         break;
      case Te_UNKNOWN:
         break;
      case Te_Atom:
         if (te->Te.Atom.name) ML_(dinfo_free)(te->Te.Atom.name);
         break;
      case Te_Field:
         if (te->Te.Field.name) ML_(dinfo_free)(te->Te.Field.name);
         if (te->Te.Field.nLoc > 0 && te->Te.Field.pos.loc)
            ML_(dinfo_free)(te->Te.Field.pos.loc);
         break;
      case Te_Bound:
         break;
      case Te_TyBase:
         if (te->Te.TyBase.name) ML_(dinfo_free)(te->Te.TyBase.name);
         break;
      case Te_TyPtr:
      case Te_TyRef:
      case Te_TyPtrMbr:
      case Te_TyRvalRef:
         break;
      case Te_TyTyDef:
         if (te->Te.TyTyDef.name) ML_(dinfo_free)(te->Te.TyTyDef.name);
         break;
      case Te_TyStOrUn:
         if (te->Te.TyStOrUn.name) ML_(dinfo_free)(te->Te.TyStOrUn.name);
         VG_(deleteXA)(te->Te.TyStOrUn.fieldRs);
         break;
      case Te_TyEnum:
         if (te->Te.TyEnum.name) ML_(dinfo_free)(te->Te.TyEnum.name);
         if (te->Te.TyEnum.atomRs) VG_(deleteXA)(te->Te.TyEnum.atomRs);
         break;
      case Te_TyArray:
         if (te->Te.TyArray.boundRs) VG_(deleteXA)(te->Te.TyArray.boundRs);
         break;
      case Te_TyFn:
         break;
      case Te_TyQual:
         break;
      case Te_TyVoid:
         break;
      default:
         vg_assert(0);
   }
   /* Now clear it out and set to Te_EMPTY. */
   saved_cuOff = te->cuOff;
   VG_(memset)(te, 0, sizeof(*te));
   te->cuOff = saved_cuOff;
   te->tag = Te_EMPTY;
}


/* How big is this type?  If .b in the returned struct is False, the
   size is unknown. */

static MaybeULong mk_MaybeULong_Nothing ( void ) {
   MaybeULong mul;
   mul.ul = 0;
   mul.b  = False;
   return mul;
}
static MaybeULong mk_MaybeULong_Just ( ULong ul ) {
   MaybeULong mul;
   mul.ul = ul;
   mul.b  = True;
   return mul;
}
static MaybeULong mul_MaybeULong ( MaybeULong mul1, MaybeULong mul2 ) {
   if (!mul1.b) { vg_assert(mul1.ul == 0); return mul1; }
   if (!mul2.b) { vg_assert(mul2.ul == 0); return mul2; }
   mul1.ul *= mul2.ul;
   return mul1;
}

MaybeULong ML_(sizeOfType)( const XArray* /* of TyEnt */ tyents,
                            UWord cuOff )
{
   Word       i;
   MaybeULong eszB;
   TyEnt*     ent = ML_(TyEnts__index_by_cuOff)(tyents, NULL, cuOff);
   TyEnt*     ent2;
   vg_assert(ent);
   vg_assert(ML_(TyEnt__is_type)(ent));
   switch (ent->tag) {
      case Te_TyBase:
         vg_assert(ent->Te.TyBase.szB > 0);
         return mk_MaybeULong_Just( ent->Te.TyBase.szB );
      case Te_TyQual:
         return ML_(sizeOfType)( tyents, ent->Te.TyQual.typeR );
      case Te_TyTyDef:
         ent2 = ML_(TyEnts__index_by_cuOff)(tyents, NULL,
                                            ent->Te.TyTyDef.typeR);
         vg_assert(ent2);
         if (ent2->tag == Te_UNKNOWN)
            return mk_MaybeULong_Nothing(); /*UNKNOWN*/
         return ML_(sizeOfType)( tyents, ent->Te.TyTyDef.typeR );
      case Te_TyPtr:
      case Te_TyRef:
      case Te_TyPtrMbr:
      case Te_TyRvalRef:
         vg_assert(ent->Te.TyPorR.szB == 4 || ent->Te.TyPorR.szB == 8);
         return mk_MaybeULong_Just( ent->Te.TyPorR.szB );
      case Te_TyStOrUn:
         return ent->Te.TyStOrUn.complete
                   ? mk_MaybeULong_Just( ent->Te.TyStOrUn.szB )
                   : mk_MaybeULong_Nothing();
      case Te_TyEnum:
         return mk_MaybeULong_Just( ent->Te.TyEnum.szB );
      case Te_TyArray:
         ent2 = ML_(TyEnts__index_by_cuOff)(tyents, NULL,
                                            ent->Te.TyArray.typeR);
         vg_assert(ent2);
         if (ent2->tag == Te_UNKNOWN)
            return mk_MaybeULong_Nothing(); /*UNKNOWN*/
         eszB = ML_(sizeOfType)( tyents, ent->Te.TyArray.typeR );
         for (i = 0; i < VG_(sizeXA)( ent->Te.TyArray.boundRs ); i++) {
            UWord bo_cuOff
               = *(UWord*)VG_(indexXA)(ent->Te.TyArray.boundRs, i);
            TyEnt* bo
              = ML_(TyEnts__index_by_cuOff)( tyents, NULL, bo_cuOff );
            vg_assert(bo);
            vg_assert(bo->tag == Te_Bound);
            if (!(bo->Te.Bound.knownL && bo->Te.Bound.knownU))
               return mk_MaybeULong_Nothing(); /*UNKNOWN*/
            eszB = mul_MaybeULong( 
                      eszB,
                      mk_MaybeULong_Just( (ULong)(bo->Te.Bound.boundU 
                                                  - bo->Te.Bound.boundL + 1) ));
         }
         return eszB;
      case Te_TyVoid:
         return mk_MaybeULong_Nothing(); /*UNKNOWN*/
      default:
         VG_(printf)("ML_(sizeOfType): unhandled: ");
         ML_(pp_TyEnt)(ent);
         VG_(printf)("\n");
         vg_assert(0);
   }
}


/* Describe where in the type 'offset' falls.  Caller must
   deallocate the resulting XArray. */

static void copy_UWord_into_XA ( XArray* /* of HChar */ xa,
                                 UWord uw ) {
   HChar buf[32];     // large enough 
   VG_(sprintf)(buf, "%lu", uw);
   VG_(addBytesToXA)( xa, buf, VG_(strlen)(buf));
}

XArray* /*HChar*/ ML_(describe_type)( /*OUT*/PtrdiffT* residual_offset,
                                      const XArray* /* of TyEnt */ tyents,
                                      UWord ty_cuOff, 
                                      PtrdiffT offset )
{
   TyEnt*  ty;
   XArray* xa = VG_(newXA)( ML_(dinfo_zalloc), "di.tytypes.dt.1",
                            ML_(dinfo_free),
                            sizeof(HChar) );

   ty = ML_(TyEnts__index_by_cuOff)(tyents, NULL, ty_cuOff);

   while (True) {
      vg_assert(ty);
      vg_assert(ML_(TyEnt__is_type)(ty));

      switch (ty->tag) {

         /* These are all atomic types; there is nothing useful we can
            do. */
         case Te_TyEnum:
         case Te_TyFn:
         case Te_TyVoid:
         case Te_TyPtr:
         case Te_TyRef:
         case Te_TyPtrMbr:
         case Te_TyRvalRef:
         case Te_TyBase:
            goto done;

         case Te_TyStOrUn: {
            Word       i;
            GXResult   res;
            MaybeULong mul;
            XArray*    fieldRs;
            UWord      fieldR;
            TyEnt*     field = NULL;
            PtrdiffT   offMin = 0, offMax1 = 0;
            if (!ty->Te.TyStOrUn.isStruct) goto done;
            fieldRs = ty->Te.TyStOrUn.fieldRs;
            if (VG_(sizeXA)(fieldRs) == 0
                && (ty->Te.TyStOrUn.typeR == 0)) goto done;
            for (i = 0; i < VG_(sizeXA)( fieldRs ); i++ ) {
               fieldR = *(UWord*)VG_(indexXA)( fieldRs, i );
               field = ML_(TyEnts__index_by_cuOff)(tyents, NULL, fieldR);
               vg_assert(field);
               vg_assert(field->tag == Te_Field);
               vg_assert(field->Te.Field.nLoc < 0
                         || (field->Te.Field.nLoc > 0
                             && field->Te.Field.pos.loc));
               if (field->Te.Field.nLoc == -1) {
                  res.kind = GXR_Addr;
                  res.word = field->Te.Field.pos.offset;
               } else {
                  /* Re data_bias in this call, we should really send in
                     a legitimate value.  But the expression is expected
                     to be a constant expression, evaluation of which
                     will not need to use DW_OP_addr and hence we can
                     avoid the trouble of plumbing the data bias through
                     to this point (if, indeed, it has any meaning; from
                     which DebugInfo would we take the data bias? */
                   res =  ML_(evaluate_Dwarf3_Expr)(
                          field->Te.Field.pos.loc, field->Te.Field.nLoc,
                          NULL/*fbGX*/, NULL/*RegSummary*/,
                          0/*data_bias*/,
                          True/*push_initial_zero*/);
                  if (0) {
                     VG_(printf)("QQQ ");
                     ML_(pp_GXResult)(res);
                     VG_(printf)("\n");
                  }
               }
               if (res.kind != GXR_Addr)
                  continue;
               mul = ML_(sizeOfType)( tyents, field->Te.Field.typeR );
               if (mul.b != True)
                  goto done; /* size of field is unknown (?!) */
               offMin  = res.word;
               offMax1 = offMin + (PtrdiffT)mul.ul;
               if (offMin == offMax1)
                  continue;
               vg_assert(offMin < offMax1);
               if (offset >= offMin && offset < offMax1)
                  break;
            }
            /* Did we find a suitable field? */
            vg_assert(i >= 0 && i <= VG_(sizeXA)( fieldRs ));
            if (i == VG_(sizeXA)( fieldRs )) {
               ty = ML_(TyEnts__index_by_cuOff)(tyents, NULL,
                                                   ty->Te.TyStOrUn.typeR);
               vg_assert(ty);
               if (ty->tag == Te_UNKNOWN) goto done;
               vg_assert(ML_(TyEnt__is_type)(ty));
               continue;
            }
            /* Yes.  'field' is it. */
            vg_assert(field);
            if (!field->Te.Field.name) goto done;
            VG_(addBytesToXA)( xa, ".", 1 );
            VG_(addBytesToXA)( xa, field->Te.Field.name,
                               VG_(strlen)(field->Te.Field.name) );
            offset -= offMin;
            ty = ML_(TyEnts__index_by_cuOff)(tyents, NULL,
                                             field->Te.Field.typeR );
            vg_assert(ty);
            if (ty->tag == Te_UNKNOWN) goto done;
            /* keep going; look inside the field. */
            break;
         }

         case Te_TyArray: {
            MaybeULong mul;
            UWord      size, eszB, ix;
            UWord      boundR;
            TyEnt*     elemTy;
            TyEnt*     bound;
            /* Just deal with the simple, common C-case: 1-D array,
               zero based, known size. */
            elemTy = ML_(TyEnts__index_by_cuOff)(tyents, NULL, 
                                                 ty->Te.TyArray.typeR);
            vg_assert(elemTy);
            if (elemTy->tag == Te_UNKNOWN) goto done;
            vg_assert(ML_(TyEnt__is_type)(elemTy));
            if (!ty->Te.TyArray.boundRs)
               goto done;
            if (VG_(sizeXA)( ty->Te.TyArray.boundRs ) != 1) goto done;
            boundR = *(UWord*)VG_(indexXA)( ty->Te.TyArray.boundRs, 0 );
            bound = ML_(TyEnts__index_by_cuOff)(tyents, NULL, boundR);
            vg_assert(bound);
            vg_assert(bound->tag == Te_Bound);
            if (!(bound->Te.Bound.knownL && bound->Te.Bound.knownU
                  && bound->Te.Bound.boundL == 0
                  && bound->Te.Bound.boundU >= bound->Te.Bound.boundL))
               goto done;
            size = bound->Te.Bound.boundU - bound->Te.Bound.boundL + 1;
            vg_assert(size >= 1);
            mul = ML_(sizeOfType)( tyents, ty->Te.TyArray.typeR );
            if (mul.b != True)
               goto done; /* size of element type not known */
            eszB = mul.ul;
            if (eszB == 0) goto done;
            ix = offset / eszB;
            VG_(addBytesToXA)( xa, "[", 1 );
            copy_UWord_into_XA( xa, ix );
            VG_(addBytesToXA)( xa, "]", 1 );
            ty = elemTy;
            offset -= ix * eszB;
            /* keep going; look inside the array element. */
            break;
         }

         case Te_TyQual: {
            ty = ML_(TyEnts__index_by_cuOff)(tyents, NULL,
                                             ty->Te.TyQual.typeR);
            vg_assert(ty);
            if (ty->tag == Te_UNKNOWN) goto done;
            break;
         }

         case Te_TyTyDef: {
            ty = ML_(TyEnts__index_by_cuOff)(tyents, NULL,
                                             ty->Te.TyTyDef.typeR);
            vg_assert(ty);
            if (ty->tag == Te_UNKNOWN) goto done;
            break;
         }

         default: {
            VG_(printf)("ML_(describe_type): unhandled: ");
            ML_(pp_TyEnt)(ty);
            VG_(printf)("\n");
            vg_assert(0);
         }

      }
   }

  done:
   *residual_offset = offset;
   VG_(addBytesToXA)( xa, "\0", 1 );
   return xa;
}

/*--------------------------------------------------------------------*/
/*--- end                                                tytypes.c ---*/
/*--------------------------------------------------------------------*/
