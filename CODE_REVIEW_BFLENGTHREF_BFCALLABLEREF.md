# Code Review: BFLengthRef and BFCallableRef

**Date:** 2026-01-31
**Files Reviewed:** `bitfactory/bitfactory.py` (lines 410-497)
**Status:** ✅ **IMPLEMENTED** - All recommendations have been applied.

## Overview

This review examines the `BFLengthRef` and `BFCallableRef` classes in the bitfactory library. These classes provide computed fields that reference external containers in the binary structure tree.

## Summary of Findings

| Issue | Severity | Type | Status |
|-------|----------|------|--------|
| Code duplication between classes | Medium | Architecture | ✅ Fixed |
| Misleading `_get_children()` name | Low | Code Quality | ✅ Fixed |
| Missing error handling for invalid paths | High | Bug | ✅ Fixed |
| Missing input validation | Medium | Bug | ✅ Fixed |
| Side effects in property getter | Low | Code Smell | ✅ Fixed |
| Redundant method parameter | Low | Code Quality | ✅ Fixed |
| BFLengthRef duplicates BFCallableRef logic | Medium | Architecture | ✅ Fixed |
| Incorrect type annotation | Low | Code Quality | ✅ Fixed |

---

## Detailed Findings

### 1. Significant Code Duplication (Medium Severity)

**Location:** `bitfactory.py:410-453` and `bitfactory.py:455-497`

The two classes share nearly identical code:

| Component | BFLengthRef | BFCallableRef | Identical? |
|-----------|-------------|---------------|------------|
| `_get_root()` | Lines 419-422 | Lines 464-467 | Yes |
| `_get_children()` | Lines 424-433 | Lines 469-478 | Yes |
| `pack()` structure | Lines 435-438 | Lines 480-483 | ~90% same |
| `value` property | Lines 440-444 | Lines 485-489 | ~90% same |
| `pretty_print()` | Lines 449-452 | Lines 494-497 | ~95% same |

The only functional difference is:
- `BFLengthRef` computes `len(children.pack())`
- `BFCallableRef` computes `self._func(children.pack())`

**Recommendation:** Extract a shared base class `BFRefBase` that handles path resolution, with subclasses implementing only the computation logic.

---

### 2. Misleading Method Name (Low Severity)

**Location:** `bitfactory.py:424-433` and `bitfactory.py:469-478`

In `BFContainer`, `_get_children()` returns a **list** of child objects. However, in both `BFLengthRef` and `BFCallableRef`, `_get_children()` returns a **single container**:

```python
# BFContainer._get_children() returns a list:
def _get_children(self):
    return list(iter(self._children.values()))[:]

# BFLengthRef._get_children() returns a single object:
def _get_children(self):
    # ... path resolution ...
    return obj  # Single object, not a list
```

This inconsistency violates the Liskov Substitution Principle.

**Recommendation:** Rename to `_resolve_ref()` or `_get_target()`.

---

### 3. Missing Error Handling for Invalid Paths (High Severity)

**Location:** `bitfactory.py:430-431` and `bitfactory.py:475-476`

If the `container_ref` path is invalid, a bare `KeyError` is raised with no context:

```python
def _get_children(self):
    # ...
    for part in path_parts:
        obj = obj._children[part]  # KeyError if 'part' doesn't exist
    return obj
```

**Example failure:**
```python
bf = BFContainer()
bf.len = BFLengthRef(BFUInt16(), "nonexistent_path")
bf.pack()  # Raises: KeyError: 'nonexistent_path'
```

**Recommendation:**
```python
try:
    obj = obj._children[part]
except KeyError:
    raise BFTypeException(f"Invalid reference path: '{self._ref}' - component '{part}' not found")
```

---

### 4. Missing Input Validation (Medium Severity)

**Location:** `bitfactory.py:413-416` and `bitfactory.py:458-462`

Neither class validates constructor arguments:

```python
# These will fail later with unhelpful errors:
BFLengthRef(BFUInt16(), None)           # AttributeError on pack()
BFLengthRef(BFUInt16(), "")             # Empty string causes issues
BFLengthRef(BFUInt16(), 123)            # Wrong type
BFCallableRef(BFUInt16(), "not_func", "path")  # TypeError on pack()
```

**Recommendation:**
```python
def __init__(self, field, container_ref):
    if not isinstance(container_ref, str) or not container_ref:
        raise BFTypeException("container_ref must be a non-empty string")
```

---

### 5. Side Effects in Property Getter (Low Severity)

**Location:** `bitfactory.py:440-444` and `bitfactory.py:485-489`

The `value` property mutates internal state:

```python
@property
def value(self):
    children = self._get_children()
    self._field.value = len(children.pack())  # Mutation in getter
    return self._field.value
```

Properties should be idempotent. This mutation could lead to confusion about when `_field.value` is valid.

**Recommendation:** Either always recompute without caching, or use a method like `compute_value()` instead.

---

### 6. Redundant Method Parameter (Low Severity)

**Location:** `bitfactory.py:419-422` and `bitfactory.py:464-467`

```python
def _get_root(self, obj) -> BFBasicDataType:
    if obj.parent is None:
        return obj
    return self._get_root(obj.parent)
```

The `obj` parameter is always `self` on first call. This could also cause stack overflow on deeply nested structures.

**Recommendation:** Use iteration instead:
```python
def _get_root(self) -> BFContainer:
    obj = self
    while obj.parent is not None:
        obj = obj.parent
    return obj
```

---

### 7. BFLengthRef is a Special Case of BFCallableRef (Medium Severity)

`BFLengthRef` could be implemented as:
```python
BFCallableRef(field, len, container_ref)
```

**Recommendation:** Either make `BFLengthRef` inherit from `BFCallableRef` with a fixed function, or extract common functionality into a base class.

---

### 8. Incorrect Type Annotation (Low Severity)

**Location:** `bitfactory.py:419` and `bitfactory.py:464`

```python
def _get_root(self, obj) -> BFBasicDataType:  # Should be -> BFContainer
```

The method always returns a `BFContainer`.

---

## Recommended Refactored Architecture

```python
class BFRefBase(BFContainer):
    """Base class for reference-based computed fields."""

    def __init__(self, field, container_ref: str):
        super().__init__()
        if not isinstance(container_ref, str) or not container_ref:
            raise BFTypeException("container_ref must be a non-empty string")
        self._field = field
        self._ref = container_ref

    def _get_root(self) -> 'BFContainer':
        """Navigate to the root of the container tree."""
        obj = self
        while obj.parent is not None:
            obj = obj.parent
        return obj

    def _resolve_ref(self) -> 'BFContainer':
        """Resolve the reference path to the target container."""
        obj = self._get_root()
        for part in self._ref.split("."):
            try:
                obj = obj._children[part]
            except KeyError:
                raise BFTypeException(
                    f"Invalid reference path: '{self._ref}' - '{part}' not found"
                )
        return obj

    @abc.abstractmethod
    def _compute_value(self, packed_data: bytes) -> int:
        """Compute the field value from packed data."""
        pass

    def pack(self) -> bytes:
        target = self._resolve_ref()
        self._field.value = self._compute_value(target.pack())
        return self._field.pack()

    @property
    def value(self) -> int:
        target = self._resolve_ref()
        return self._compute_value(target.pack())

    def __str__(self):
        return self.pretty_print()

    def pretty_print(self, indent=0):
        return " " * indent + f"+{self.name} value: 0x{self.value:0x}\n"


class BFLengthRef(BFRefBase):
    """Length field referencing external container."""

    def _compute_value(self, packed_data: bytes) -> int:
        return len(packed_data)

    def pretty_print(self, indent=0):
        return " " * indent + f"+{self.name} length: 0x{self.value:0x}\n"


class BFCallableRef(BFRefBase):
    """Computed field using callable on external container."""

    def __init__(self, field, func, container_ref: str):
        super().__init__(field, container_ref)
        if not callable(func):
            raise BFTypeException("func must be callable")
        self._func = func

    def _compute_value(self, packed_data: bytes) -> int:
        return self._func(packed_data)
```

## Conclusion

The library works correctly for valid inputs (all tests pass), but lacks defensive programming practices. The most impactful improvements would be:

1. **High Priority:** Add error handling for invalid reference paths
2. **Medium Priority:** Extract shared code into a base class
3. **Medium Priority:** Add input validation in constructors

These changes would make the library more robust and maintainable without changing its public API.

---

## Implementation Status

All recommendations have been implemented:

### Changes Made

1. **New `BFRefBase` class** (`bitfactory/bitfactory.py`):
   - Shared base class for reference-based computed fields
   - Input validation for `container_ref` (must be non-empty string)
   - `_get_root()` now uses iteration instead of recursion
   - `_resolve_ref()` replaces `_get_children()` with proper error handling
   - Abstract `_compute_value()` method for subclasses

2. **Refactored `BFLengthRef`**:
   - Now extends `BFRefBase`
   - Only implements `_compute_value()` returning `len(packed_data)`
   - ~80% code reduction

3. **Refactored `BFCallableRef`**:
   - Now extends `BFRefBase`
   - Adds validation that `func` is callable
   - Only implements `_compute_value()` calling `self._func(packed_data)`
   - ~70% code reduction

4. **New `BFRefBase` exported** from `bitfactory/__init__.py` for extensibility

5. **New validation tests** (`tests/test_bitfactory.py`):
   - `test_invalid_container_ref_empty_string`
   - `test_invalid_container_ref_none`
   - `test_invalid_container_ref_non_string`
   - `test_invalid_func_not_callable`
   - `test_invalid_reference_path`
   - `test_invalid_nested_reference_path`

### Test Results

All 17 tests pass (11 original + 6 new validation tests).
