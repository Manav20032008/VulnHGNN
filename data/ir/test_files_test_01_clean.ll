; ModuleID = 'test_files/test_01_clean.c'
source_filename = "test_files/test_01_clean.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [12 x i8] c"Result: %d\0A\00", align 1, !dbg !0
@.str.1 = private unnamed_addr constant [19 x i8] c"Pointer value: %d\0A\00", align 1, !dbg !7

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @main() #0 !dbg !26 {
  %1 = alloca i32, align 4
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  store i32 0, ptr %1, align 4
  call void @llvm.dbg.declare(metadata ptr %2, metadata !30, metadata !DIExpression()), !dbg !31
  store i32 10, ptr %2, align 4, !dbg !31
  call void @llvm.dbg.declare(metadata ptr %3, metadata !32, metadata !DIExpression()), !dbg !33
  store i32 20, ptr %3, align 4, !dbg !33
  call void @llvm.dbg.declare(metadata ptr %4, metadata !34, metadata !DIExpression()), !dbg !35
  %6 = load i32, ptr %2, align 4, !dbg !36
  %7 = load i32, ptr %3, align 4, !dbg !37
  %8 = add nsw i32 %6, %7, !dbg !38
  store i32 %8, ptr %4, align 4, !dbg !35
  %9 = load i32, ptr %3, align 4, !dbg !39
  %10 = icmp ne i32 %9, 0, !dbg !41
  br i1 %10, label %11, label %16, !dbg !42

11:                                               ; preds = %0
  %12 = load i32, ptr %4, align 4, !dbg !43
  %13 = load i32, ptr %3, align 4, !dbg !45
  %14 = sdiv i32 %12, %13, !dbg !46
  %15 = call i32 (ptr, ...) @printf(ptr noundef @.str, i32 noundef %14), !dbg !47
  br label %16, !dbg !48

16:                                               ; preds = %11, %0
  call void @llvm.dbg.declare(metadata ptr %5, metadata !49, metadata !DIExpression()), !dbg !50
  %17 = call noalias ptr @malloc(i64 noundef 4) #5, !dbg !51
  store ptr %17, ptr %5, align 8, !dbg !50
  %18 = load ptr, ptr %5, align 8, !dbg !52
  %19 = icmp ne ptr %18, null, !dbg !54
  br i1 %19, label %20, label %26, !dbg !55

20:                                               ; preds = %16
  %21 = load ptr, ptr %5, align 8, !dbg !56
  store i32 100, ptr %21, align 4, !dbg !58
  %22 = load ptr, ptr %5, align 8, !dbg !59
  %23 = load i32, ptr %22, align 4, !dbg !60
  %24 = call i32 (ptr, ...) @printf(ptr noundef @.str.1, i32 noundef %23), !dbg !61
  %25 = load ptr, ptr %5, align 8, !dbg !62
  call void @free(ptr noundef %25) #6, !dbg !63
  br label %26, !dbg !64

26:                                               ; preds = %20, %16
  ret i32 0, !dbg !65
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

declare i32 @printf(ptr noundef, ...) #2

; Function Attrs: nounwind allocsize(0)
declare noalias ptr @malloc(i64 noundef) #3

; Function Attrs: nounwind
declare void @free(ptr noundef) #4

attributes #0 = { noinline nounwind uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { nounwind allocsize(0) "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #4 = { nounwind "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #5 = { nounwind allocsize(0) }
attributes #6 = { nounwind }

!llvm.dbg.cu = !{!12}
!llvm.module.flags = !{!18, !19, !20, !21, !22, !23, !24}
!llvm.ident = !{!25}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(scope: null, file: !2, line: 14, type: !3, isLocal: true, isDefinition: true)
!2 = !DIFile(filename: "test_files/test_01_clean.c", directory: "/home/manavtejani/Desktop/Academics/Automata/VulnHGNN", checksumkind: CSK_MD5, checksum: "b49ef49990a1f10ab3d1c52f5b362afd")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 96, elements: !5)
!4 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!5 = !{!6}
!6 = !DISubrange(count: 12)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(scope: null, file: !2, line: 20, type: !9, isLocal: true, isDefinition: true)
!9 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 152, elements: !10)
!10 = !{!11}
!11 = !DISubrange(count: 19)
!12 = distinct !DICompileUnit(language: DW_LANG_C11, file: !2, producer: "Ubuntu clang version 18.1.3 (1ubuntu1)", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, retainedTypes: !13, globals: !17, splitDebugInlining: false, nameTableKind: None)
!13 = !{!14, !16}
!14 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !15, size: 64)
!15 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!16 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!17 = !{!0, !7}
!18 = !{i32 7, !"Dwarf Version", i32 5}
!19 = !{i32 2, !"Debug Info Version", i32 3}
!20 = !{i32 1, !"wchar_size", i32 4}
!21 = !{i32 8, !"PIC Level", i32 2}
!22 = !{i32 7, !"PIE Level", i32 2}
!23 = !{i32 7, !"uwtable", i32 2}
!24 = !{i32 7, !"frame-pointer", i32 2}
!25 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
!26 = distinct !DISubprogram(name: "main", scope: !2, file: !2, line: 8, type: !27, scopeLine: 8, spFlags: DISPFlagDefinition, unit: !12, retainedNodes: !29)
!27 = !DISubroutineType(types: !28)
!28 = !{!15}
!29 = !{}
!30 = !DILocalVariable(name: "a", scope: !26, file: !2, line: 9, type: !15)
!31 = !DILocation(line: 9, column: 9, scope: !26)
!32 = !DILocalVariable(name: "b", scope: !26, file: !2, line: 10, type: !15)
!33 = !DILocation(line: 10, column: 9, scope: !26)
!34 = !DILocalVariable(name: "sum", scope: !26, file: !2, line: 11, type: !15)
!35 = !DILocation(line: 11, column: 9, scope: !26)
!36 = !DILocation(line: 11, column: 15, scope: !26)
!37 = !DILocation(line: 11, column: 19, scope: !26)
!38 = !DILocation(line: 11, column: 17, scope: !26)
!39 = !DILocation(line: 13, column: 9, scope: !40)
!40 = distinct !DILexicalBlock(scope: !26, file: !2, line: 13, column: 9)
!41 = !DILocation(line: 13, column: 11, scope: !40)
!42 = !DILocation(line: 13, column: 9, scope: !26)
!43 = !DILocation(line: 14, column: 32, scope: !44)
!44 = distinct !DILexicalBlock(scope: !40, file: !2, line: 13, column: 17)
!45 = !DILocation(line: 14, column: 38, scope: !44)
!46 = !DILocation(line: 14, column: 36, scope: !44)
!47 = !DILocation(line: 14, column: 9, scope: !44)
!48 = !DILocation(line: 15, column: 5, scope: !44)
!49 = !DILocalVariable(name: "p", scope: !26, file: !2, line: 17, type: !14)
!50 = !DILocation(line: 17, column: 10, scope: !26)
!51 = !DILocation(line: 17, column: 21, scope: !26)
!52 = !DILocation(line: 18, column: 9, scope: !53)
!53 = distinct !DILexicalBlock(scope: !26, file: !2, line: 18, column: 9)
!54 = !DILocation(line: 18, column: 11, scope: !53)
!55 = !DILocation(line: 18, column: 9, scope: !26)
!56 = !DILocation(line: 19, column: 10, scope: !57)
!57 = distinct !DILexicalBlock(scope: !53, file: !2, line: 18, column: 20)
!58 = !DILocation(line: 19, column: 12, scope: !57)
!59 = !DILocation(line: 20, column: 40, scope: !57)
!60 = !DILocation(line: 20, column: 39, scope: !57)
!61 = !DILocation(line: 20, column: 9, scope: !57)
!62 = !DILocation(line: 21, column: 14, scope: !57)
!63 = !DILocation(line: 21, column: 9, scope: !57)
!64 = !DILocation(line: 22, column: 5, scope: !57)
!65 = !DILocation(line: 24, column: 5, scope: !26)
