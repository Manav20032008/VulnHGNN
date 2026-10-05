; ModuleID = 'test_files/test_07_dual_369_476.c'
source_filename = "test_files/test_07_dual_369_476.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [11 x i8] c"Value: %d\0A\00", align 1, !dbg !0

; Function Attrs: noinline nounwind uwtable
define dso_local void @process_data(i32 noundef %0) #0 !dbg !20 {
  %2 = alloca i32, align 4
  %3 = alloca ptr, align 8
  %4 = alloca i32, align 4
  store i32 %0, ptr %2, align 4
  call void @llvm.dbg.declare(metadata ptr %2, metadata !24, metadata !DIExpression()), !dbg !25
  call void @llvm.dbg.declare(metadata ptr %3, metadata !26, metadata !DIExpression()), !dbg !27
  %5 = call noalias ptr @malloc(i64 noundef 4) #5, !dbg !28
  store ptr %5, ptr %3, align 8, !dbg !27
  %6 = load ptr, ptr %3, align 8, !dbg !29
  store i32 500, ptr %6, align 4, !dbg !30
  call void @llvm.dbg.declare(metadata ptr %4, metadata !31, metadata !DIExpression()), !dbg !32
  %7 = load ptr, ptr %3, align 8, !dbg !33
  %8 = load i32, ptr %7, align 4, !dbg !34
  %9 = load i32, ptr %2, align 4, !dbg !35
  %10 = sdiv i32 %8, %9, !dbg !36
  store i32 %10, ptr %4, align 4, !dbg !32
  %11 = load i32, ptr %4, align 4, !dbg !37
  %12 = call i32 (ptr, ...) @printf(ptr noundef @.str, i32 noundef %11), !dbg !38
  %13 = load ptr, ptr %3, align 8, !dbg !39
  call void @free(ptr noundef %13) #6, !dbg !40
  ret void, !dbg !41
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: nounwind allocsize(0)
declare noalias ptr @malloc(i64 noundef) #2

declare i32 @printf(ptr noundef, ...) #3

; Function Attrs: nounwind
declare void @free(ptr noundef) #4

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @main() #0 !dbg !42 {
  %1 = alloca i32, align 4
  store i32 0, ptr %1, align 4
  call void @process_data(i32 noundef 0), !dbg !45
  ret i32 0, !dbg !46
}

attributes #0 = { noinline nounwind uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { nounwind allocsize(0) "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #4 = { nounwind "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #5 = { nounwind allocsize(0) }
attributes #6 = { nounwind }

!llvm.dbg.cu = !{!7}
!llvm.module.flags = !{!12, !13, !14, !15, !16, !17, !18}
!llvm.ident = !{!19}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(scope: null, file: !2, line: 17, type: !3, isLocal: true, isDefinition: true)
!2 = !DIFile(filename: "test_files/test_07_dual_369_476.c", directory: "/home/manavtejani/Desktop/Academics/Automata/VulnHGNN", checksumkind: CSK_MD5, checksum: "99194dfc4c27fc6b37ae14848b4350d1")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 88, elements: !5)
!4 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!5 = !{!6}
!6 = !DISubrange(count: 11)
!7 = distinct !DICompileUnit(language: DW_LANG_C11, file: !2, producer: "Ubuntu clang version 18.1.3 (1ubuntu1)", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, retainedTypes: !8, globals: !11, splitDebugInlining: false, nameTableKind: None)
!8 = !{!9}
!9 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !10, size: 64)
!10 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!11 = !{!0}
!12 = !{i32 7, !"Dwarf Version", i32 5}
!13 = !{i32 2, !"Debug Info Version", i32 3}
!14 = !{i32 1, !"wchar_size", i32 4}
!15 = !{i32 8, !"PIC Level", i32 2}
!16 = !{i32 7, !"PIE Level", i32 2}
!17 = !{i32 7, !"uwtable", i32 2}
!18 = !{i32 7, !"frame-pointer", i32 2}
!19 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
!20 = distinct !DISubprogram(name: "process_data", scope: !2, file: !2, line: 8, type: !21, scopeLine: 8, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !7, retainedNodes: !23)
!21 = !DISubroutineType(types: !22)
!22 = !{null, !10}
!23 = !{}
!24 = !DILocalVariable(name: "divisor", arg: 1, scope: !20, file: !2, line: 8, type: !10)
!25 = !DILocation(line: 8, column: 23, scope: !20)
!26 = !DILocalVariable(name: "data", scope: !20, file: !2, line: 9, type: !9)
!27 = !DILocation(line: 9, column: 10, scope: !20)
!28 = !DILocation(line: 9, column: 24, scope: !20)
!29 = !DILocation(line: 12, column: 6, scope: !20)
!30 = !DILocation(line: 12, column: 11, scope: !20)
!31 = !DILocalVariable(name: "result", scope: !20, file: !2, line: 15, type: !10)
!32 = !DILocation(line: 15, column: 9, scope: !20)
!33 = !DILocation(line: 15, column: 19, scope: !20)
!34 = !DILocation(line: 15, column: 18, scope: !20)
!35 = !DILocation(line: 15, column: 26, scope: !20)
!36 = !DILocation(line: 15, column: 24, scope: !20)
!37 = !DILocation(line: 17, column: 27, scope: !20)
!38 = !DILocation(line: 17, column: 5, scope: !20)
!39 = !DILocation(line: 18, column: 10, scope: !20)
!40 = !DILocation(line: 18, column: 5, scope: !20)
!41 = !DILocation(line: 19, column: 1, scope: !20)
!42 = distinct !DISubprogram(name: "main", scope: !2, file: !2, line: 21, type: !43, scopeLine: 21, spFlags: DISPFlagDefinition, unit: !7)
!43 = !DISubroutineType(types: !44)
!44 = !{!10}
!45 = !DILocation(line: 22, column: 5, scope: !42)
!46 = !DILocation(line: 23, column: 5, scope: !42)
