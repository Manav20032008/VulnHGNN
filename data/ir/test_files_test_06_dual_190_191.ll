; ModuleID = 'test_files/test_06_dual_190_191.c'
source_filename = "test_files/test_06_dual_190_191.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [14 x i8] c"O: %d, U: %d\0A\00", align 1, !dbg !0

; Function Attrs: noinline nounwind uwtable
define dso_local void @complex_math(i32 noundef %0, i32 noundef %1) #0 !dbg !17 {
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  %5 = alloca i32, align 4
  %6 = alloca i32, align 4
  store i32 %0, ptr %3, align 4
  call void @llvm.dbg.declare(metadata ptr %3, metadata !22, metadata !DIExpression()), !dbg !23
  store i32 %1, ptr %4, align 4
  call void @llvm.dbg.declare(metadata ptr %4, metadata !24, metadata !DIExpression()), !dbg !25
  call void @llvm.dbg.declare(metadata ptr %5, metadata !26, metadata !DIExpression()), !dbg !27
  %7 = load i32, ptr %3, align 4, !dbg !28
  %8 = mul nsw i32 %7, 100, !dbg !29
  store i32 %8, ptr %5, align 4, !dbg !27
  call void @llvm.dbg.declare(metadata ptr %6, metadata !30, metadata !DIExpression()), !dbg !31
  %9 = load i32, ptr %4, align 4, !dbg !32
  %10 = sub nsw i32 %9, 100000, !dbg !33
  store i32 %10, ptr %6, align 4, !dbg !31
  %11 = load i32, ptr %5, align 4, !dbg !34
  %12 = load i32, ptr %6, align 4, !dbg !35
  %13 = call i32 (ptr, ...) @printf(ptr noundef @.str, i32 noundef %11, i32 noundef %12), !dbg !36
  ret void, !dbg !37
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

declare i32 @printf(ptr noundef, ...) #2

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @main() #0 !dbg !38 {
  %1 = alloca i32, align 4
  store i32 0, ptr %1, align 4
  call void @complex_math(i32 noundef 1073741823, i32 noundef -2147483598), !dbg !41
  ret i32 0, !dbg !42
}

attributes #0 = { noinline nounwind uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.dbg.cu = !{!7}
!llvm.module.flags = !{!9, !10, !11, !12, !13, !14, !15}
!llvm.ident = !{!16}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(scope: null, file: !2, line: 15, type: !3, isLocal: true, isDefinition: true)
!2 = !DIFile(filename: "test_files/test_06_dual_190_191.c", directory: "/home/manavtejani/Desktop/Academics/Automata/VulnHGNN", checksumkind: CSK_MD5, checksum: "727d1c5d024e6c846785e2fe95d589da")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 112, elements: !5)
!4 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!5 = !{!6}
!6 = !DISubrange(count: 14)
!7 = distinct !DICompileUnit(language: DW_LANG_C11, file: !2, producer: "Ubuntu clang version 18.1.3 (1ubuntu1)", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, globals: !8, splitDebugInlining: false, nameTableKind: None)
!8 = !{!0}
!9 = !{i32 7, !"Dwarf Version", i32 5}
!10 = !{i32 2, !"Debug Info Version", i32 3}
!11 = !{i32 1, !"wchar_size", i32 4}
!12 = !{i32 8, !"PIC Level", i32 2}
!13 = !{i32 7, !"PIE Level", i32 2}
!14 = !{i32 7, !"uwtable", i32 2}
!15 = !{i32 7, !"frame-pointer", i32 2}
!16 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
!17 = distinct !DISubprogram(name: "complex_math", scope: !2, file: !2, line: 8, type: !18, scopeLine: 8, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !7, retainedNodes: !21)
!18 = !DISubroutineType(types: !19)
!19 = !{null, !20, !20}
!20 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!21 = !{}
!22 = !DILocalVariable(name: "x", arg: 1, scope: !17, file: !2, line: 8, type: !20)
!23 = !DILocation(line: 8, column: 23, scope: !17)
!24 = !DILocalVariable(name: "y", arg: 2, scope: !17, file: !2, line: 8, type: !20)
!25 = !DILocation(line: 8, column: 30, scope: !17)
!26 = !DILocalVariable(name: "over", scope: !17, file: !2, line: 10, type: !20)
!27 = !DILocation(line: 10, column: 9, scope: !17)
!28 = !DILocation(line: 10, column: 16, scope: !17)
!29 = !DILocation(line: 10, column: 18, scope: !17)
!30 = !DILocalVariable(name: "under", scope: !17, file: !2, line: 13, type: !20)
!31 = !DILocation(line: 13, column: 9, scope: !17)
!32 = !DILocation(line: 13, column: 17, scope: !17)
!33 = !DILocation(line: 13, column: 19, scope: !17)
!34 = !DILocation(line: 15, column: 30, scope: !17)
!35 = !DILocation(line: 15, column: 36, scope: !17)
!36 = !DILocation(line: 15, column: 5, scope: !17)
!37 = !DILocation(line: 16, column: 1, scope: !17)
!38 = distinct !DISubprogram(name: "main", scope: !2, file: !2, line: 18, type: !39, scopeLine: 18, spFlags: DISPFlagDefinition, unit: !7)
!39 = !DISubroutineType(types: !40)
!40 = !{!20}
!41 = !DILocation(line: 19, column: 5, scope: !38)
!42 = !DILocation(line: 20, column: 5, scope: !38)
