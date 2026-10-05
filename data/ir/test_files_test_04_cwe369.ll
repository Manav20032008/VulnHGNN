; ModuleID = 'test_files/test_04_cwe369.c'
source_filename = "test_files/test_04_cwe369.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [12 x i8] c"Result: %d\0A\00", align 1, !dbg !0

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @do_division(i32 noundef %0, i32 noundef %1) #0 !dbg !17 {
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  store i32 %0, ptr %3, align 4
  call void @llvm.dbg.declare(metadata ptr %3, metadata !22, metadata !DIExpression()), !dbg !23
  store i32 %1, ptr %4, align 4
  call void @llvm.dbg.declare(metadata ptr %4, metadata !24, metadata !DIExpression()), !dbg !25
  %5 = load i32, ptr %3, align 4, !dbg !26
  %6 = load i32, ptr %4, align 4, !dbg !27
  %7 = sdiv i32 %5, %6, !dbg !28
  ret i32 %7, !dbg !29
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @main() #0 !dbg !30 {
  %1 = alloca i32, align 4
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  store i32 0, ptr %1, align 4
  call void @llvm.dbg.declare(metadata ptr %2, metadata !33, metadata !DIExpression()), !dbg !34
  store i32 10, ptr %2, align 4, !dbg !34
  call void @llvm.dbg.declare(metadata ptr %3, metadata !35, metadata !DIExpression()), !dbg !36
  store i32 0, ptr %3, align 4, !dbg !36
  %4 = load i32, ptr %2, align 4, !dbg !37
  %5 = load i32, ptr %3, align 4, !dbg !38
  %6 = call i32 @do_division(i32 noundef %4, i32 noundef %5), !dbg !39
  %7 = call i32 (ptr, ...) @printf(ptr noundef @.str, i32 noundef %6), !dbg !40
  ret i32 0, !dbg !41
}

declare i32 @printf(ptr noundef, ...) #2

attributes #0 = { noinline nounwind uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.dbg.cu = !{!7}
!llvm.module.flags = !{!9, !10, !11, !12, !13, !14, !15}
!llvm.ident = !{!16}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(scope: null, file: !2, line: 15, type: !3, isLocal: true, isDefinition: true)
!2 = !DIFile(filename: "test_files/test_04_cwe369.c", directory: "/home/manavtejani/Desktop/Academics/Automata/VulnHGNN", checksumkind: CSK_MD5, checksum: "69e474951ae979e1d40c165644823970")
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
!17 = distinct !DISubprogram(name: "do_division", scope: !2, file: !2, line: 7, type: !18, scopeLine: 7, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !7, retainedNodes: !21)
!18 = !DISubroutineType(types: !19)
!19 = !{!20, !20, !20}
!20 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!21 = !{}
!22 = !DILocalVariable(name: "a", arg: 1, scope: !17, file: !2, line: 7, type: !20)
!23 = !DILocation(line: 7, column: 21, scope: !17)
!24 = !DILocalVariable(name: "b", arg: 2, scope: !17, file: !2, line: 7, type: !20)
!25 = !DILocation(line: 7, column: 28, scope: !17)
!26 = !DILocation(line: 9, column: 12, scope: !17)
!27 = !DILocation(line: 9, column: 16, scope: !17)
!28 = !DILocation(line: 9, column: 14, scope: !17)
!29 = !DILocation(line: 9, column: 5, scope: !17)
!30 = distinct !DISubprogram(name: "main", scope: !2, file: !2, line: 12, type: !31, scopeLine: 12, spFlags: DISPFlagDefinition, unit: !7, retainedNodes: !21)
!31 = !DISubroutineType(types: !32)
!32 = !{!20}
!33 = !DILocalVariable(name: "x", scope: !30, file: !2, line: 13, type: !20)
!34 = !DILocation(line: 13, column: 9, scope: !30)
!35 = !DILocalVariable(name: "y", scope: !30, file: !2, line: 14, type: !20)
!36 = !DILocation(line: 14, column: 9, scope: !30)
!37 = !DILocation(line: 15, column: 40, scope: !30)
!38 = !DILocation(line: 15, column: 43, scope: !30)
!39 = !DILocation(line: 15, column: 28, scope: !30)
!40 = !DILocation(line: 15, column: 5, scope: !30)
!41 = !DILocation(line: 16, column: 5, scope: !30)
