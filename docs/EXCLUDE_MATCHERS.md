# Glob Pattern Syntax

`GlobPattern` provides a restricted glob syntax designed for matching paths and URL paths.

The syntax intentionally supports a small set of operators to keep pattern matching predictable and efficient.

## Supported Patterns

### Literal text

Any character that is not part of a glob operator is treated as literal text.

```text
foo
/api/users
static/index.html
```

Literal text is matched exactly.

---

### `*` — Single-level wildcard

`*` matches zero or more characters within a single path segment.

It **does not match `/`**.

```text
*.html
/api/*.json
/static/*
```

Examples:

```text
*.html

index.html       ✓
index.htm        ✗
foo/index.html   ✗
```

```text
/api/*.json

/api/users.json  ✓
/api/test.json   ✓
/api/users/x.json ✗
```

---

### `**` — Recursive wildcard

`**` matches zero or more characters, including `/`.

It can therefore cross multiple path segments.

```text
/**
/api/**
foo**bar
```

Examples:

```text
/api/**

/api/             ✓
/api/users        ✓
/api/users/123    ✓
/api/a/b/c        ✓
```

Unlike `*`, `**` may match `/`.

---

### `**/` — Recursive directory wildcard

`**/` matches zero or more complete path segments.

This form is useful when the wildcard represents directories.

```text
**/data
usr/**/data
src/**/test/*.rs
```

Examples:

```text
usr/**/data

usr/data             ✓
usr/a/data           ✓
usr/a/b/data         ✓
usr/a/b/c/data       ✓
```

The recursive portion may match zero segments, so:

```text
usr/**/data
```

also matches:

```text
usr/data
```

---

### `?` — Single-character wildcard

`?` matches exactly one character other than `/`.

```text
file?.txt
/api/?
```

Examples:

```text
file?.txt

file1.txt   ✓
fileA.txt   ✓
file12.txt  ✗
```

`?` does not match `/`.

---

## Character Classes

### `[abc]`

A character class matches exactly one character from the specified set.

```text
[abc]
```

matches:

```text
a
b
c
```

Example:

```text
file[123].txt
```

matches:

```text
file1.txt  ✓
file2.txt  ✓
file3.txt  ✓
file4.txt  ✗
```

---

### `[a-z]`

A character range matches one character within the specified range.

```text
[a-z]
[A-Z]
[0-9]
```

Examples:

```text
file[0-9].txt

file0.txt  ✓
file5.txt  ✓
file9.txt  ✓
filea.txt  ✗
```

Multiple ranges and individual characters may be combined:

```text
[a-zA-Z0-9]
```

---

### `[^abc]`

A negated character class matches one character that is **not** in the specified set.

```text
[^abc]
```

matches:

```text
d
x
1
/
```

provided the character is not one of `a`, `b`, or `c`.

> Character classes operate on individual bytes. `/` is not implicitly excluded by negation.

---

## Groups

### `{foo,bar}`

A group matches one of several literal alternatives.

```text
{foo,bar}
```

matches either:

```text
foo
```

or:

```text
bar
```

Examples:

```text
{jpg,png,gif}
```

matches:

```text
jpg  ✓
png  ✓
gif  ✓
webp ✗
```

Groups may contain multiple alternatives:

```text
{foo,bar,baz}
```

The maximum number of alternatives is limited to **16**.

---

# Valid Patterns

The following are valid:

```text
*
**
**/
?
[abc]
[^abc]
[a-z]
{foo,bar}

*.html
**/*.html
**/data
usr/**/data
/api/*
/api/**
/api/**/users
/static/[a-z]/*
file?.txt
{foo,bar}/data
```

Literal text can be freely combined with the supported operators.

---

# Invalid Patterns

## Unclosed character class

```text
[abc
```

Invalid because `]` is missing.

```text
[a-z
```

Invalid because the character class is not closed.

Error:

```text
UnclosedCharClass
```

---

## Unclosed group

```text
{foo,bar
```

Invalid because `}` is missing.

Error:

```text
UnclosedGroup
```

---

## Too many group alternatives

The maximum number of alternatives is **16**.

Therefore:

```text
{a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p}
```

is valid.

But:

```text
{a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q}
```

is invalid.

Error:

```text
GroupOptionsLimit
```

---

## Too many recursive wildcards

The number of `**` operators is limited.

For example, if the configured limit is:

```text
MAX_DEEP_WILDCARDS = 6
```

then a pattern containing more than six `**` operators is invalid.

Error:

```text
TooManyDeepWildcards
```

---

# Unsupported Syntax

The glob syntax deliberately does **not** provide general regular-expression syntax.

The following are not glob operators:

```text
+
|
()
()
{foo|bar}
```

Groups use commas:

```text
{foo,bar}
```

not regex alternation:

```text
(foo|bar)
```

The syntax also does not support nested groups.

For example:

```text
{foo,{bar,baz}}
```

is invalid.

The supported group form is:

```text
{foo,bar,baz}
```

---

# Summary

| Pattern     | Meaning                                   |
| ----------- | ----------------------------------------- |
| `*`         | Zero or more characters except `/`        |
| `**`        | Zero or more characters, including `/`    |
| `**/`       | Zero or more complete path segments       |
| `?`         | Exactly one character except `/`          |
| `[abc]`     | One character from the set                |
| `[a-z]`     | One character in the range                |
| `[^abc]`    | One character not in the set              |
| `{foo,bar}` | One of the specified literal alternatives |
