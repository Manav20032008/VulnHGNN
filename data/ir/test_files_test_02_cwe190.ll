; ModuleID = 'test_files/test_02_cwe190.c'
source_filename = "test_files/test_02_cwe190.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [12 x i8] c"Result: %d\0A\00", align 1, !dbg !0

; Function Attrs: noinline nounwind uwtable
define dso_local void @check_overflow(i32 noundef %0) #0 !dbg !17 {
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  store i32 %0, ptr %2, align 4
  call void @llvm.dbg.declare(metadata ptr %2, metadata !22, metadata !DIExpression()), !dbg !23
  call void @llvm.dbg.declare(metadata ptr %3, metadata !24, metadata !DIExpression()), !dbg !25
  %4 = load i32, ptr %2, align 4, !dbg !26
  %5 = add nsw i32 %4, 1000, !dbg !27
  store i32 %5, ptr %3, align 4, !dbg !25
  %6 = load i32, ptr %3, align 4, !dbg !28
  %7 = call i32 (ptr, ...) @printf(ptr noundef @.str, i32 noundef %6), !dbg !29
  ret void, !dbg !30
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

declare i32 @printf(ptr noundef, ...) #2

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @main() #0 !dbg !31 {
  %1 = alloca i32, align 4
  store i32 0, ptr %1, align 4
  call void @check_overflow(i32 noundef 2147483642), !dbg !34
  ret i32 0, !dbg !35
}

attributes #0 = { noinline nounwind uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.dbg.cu = !{!7}
!llvm.module.flags = !{!9, !10, !11, !12, !13, !14, !15}
!llvm.ident = !{!16}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(scope: null, file: !2, line: 11, type: !3, isLocal: true, isDefinition: true)
!2 = !DIFile(filename: "test_files/test_02_cwe190.c", directory: "/home/manavtejani/Desktop/Academics/Automata/VulnHGNN", checksumkind: CSK_MD5, checksum: "ce22a086c5c37221d1b396ece4012b6c")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 96, elements: !5)
!4 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!5 = !{!6}
!6 = !DISubrange(count: 12)
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
!17 = distinct !DISubprogram(name: "check_overflow", scope: !2, file: !2, line: 8, type: !18, scopeLine: 8, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !7, retainedNodes: !21)
!18 = !DISubroutineType(types: !19)
!19 = !{null, !20}
!20 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!21 = !{}
!22 = !DILocalVariable(name: "input", arg: 1, scope: !17, file: !2, line: 8, type: !20)
!23 = !DILocation(line: 8, column: 25, scope: !17)
!24 = !DILocalVariable(name: "result", scope: !17, file: !2, line: 10, type: !20)
!25 = !DILocation(line: 10, column: 9, scope: !17)
!26 = !DILocation(line: 10, column: 18, scope: !17)
!27 = !DILocation(line: 10, column: 24, scope: !17)
!28 = !DILocation(line: 11, column: 28, scope: !17)
!29 = !DILocation(line: 11, column: 5, scope: !17)
!30 = !DILocation(line: 12, column: 1, scope: !17)
!31 = distinct !DISubprogram(name: "main", scope: !2, file: !2, line: 14, type: !32, scopeLine: 14, spFlags: DISPFlagDefinition, unit: !7)
!32 = !DISubroutineType(types: !33)
!33 = !{!20}
!34 = !DILocation(line: 15, column: 5, scope: !31)
!35 = !DILocation(line: 16, column: 5, scope: !31)
