from src.V2.analysis.heap_ir import (
    heap_alloc_size_operand,
    is_heap_alloc_call,
    is_heap_dealloc_call,
    ptr_arg_from_dealloc,
)


def test_operator_new_and_delete_symbols():
    assert is_heap_alloc_call("%3 = call noalias ptr @_Znwm(i64 noundef 4)")
    assert is_heap_alloc_call("%3 = call noalias ptr @_Znam(i64 noundef 64)")
    assert is_heap_dealloc_call("call void @_ZdlPv(ptr noundef %6)")
    assert ptr_arg_from_dealloc("call void @_ZdlPv(ptr noundef %6)") == "%6"


def test_malloc_still_supported():
    assert is_heap_alloc_call("%2 = call ptr @malloc(i64 16)")
    assert is_heap_dealloc_call("call void @free(ptr %2)")
    assert ptr_arg_from_dealloc("call void @free(ptr %2)") == "%2"


def test_heap_alloc_size_operand():
    tok = heap_alloc_size_operand("call noalias ptr @_Znwm(i64 noundef 99999999)")
    assert tok is not None
