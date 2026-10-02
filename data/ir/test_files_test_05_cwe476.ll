; ModuleID = 'test_files/test_05_cwe476.c'
source_filename = "test_files/test_05_cwe476.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [12 x i8] c"User Record\00", align 1, !dbg !0
@.str.1 = private unnamed_addr constant [18 x i8] c"ID: %d, Name: %s\0A\00", align 1, !dbg !7

; Function Attrs: noinline nounwind uwtable
define dso_local void @handle_record(i32 noundef %0) #0 !dbg !24 {
  %2 = alloca i32, align 4
  %3 = alloca ptr, align 8
  store i32 %0, ptr %2, align 4
  call void @llvm.dbg.declare(metadata ptr %2, metadata !29, metadata !DIExpression()), !dbg !30
  call void @llvm.dbg.declare(metadata ptr %3, metadata !31, metadata !DIExpression()), !dbg !32
  %4 = call noalias ptr @malloc(i64 noundef 64) #5, !dbg !33
  store ptr %4, ptr %3, align 8, !dbg !32
  %5 = load ptr, ptr %3, align 8, !dbg !34
  %6 = call ptr @strcpy(ptr noundef %5, ptr noundef @.str) #6, !dbg !35
  %7 = load i32, ptr %2, align 4, !dbg !36
  %8 = load ptr, ptr %3, align 8, !dbg !37
  %9 = call i32 (ptr, ...) @printf(ptr noundef @.str.1, i32 noundef %7, ptr noundef %8), !dbg !38
  %10 = load ptr, ptr %3, align 8, !dbg !39
  call void @free(ptr noundef %10) #6, !dbg !40
  ret void, !dbg !41
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: nounwind allocsize(0)
declare noalias ptr @malloc(i64 noundef) #2

; Function Attrs: nounwind
declare ptr @strcpy(ptr noundef, ptr noundef) #3

declare i32 @printf(ptr noundef, ...) #4

; Function Attrs: nounwind
declare void @free(ptr noundef) #3

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @main() #0 !dbg !42 {
  %1 = alloca i32, align 4
  store i32 0, ptr %1, align 4
  call void @handle_record(i32 noundef 1), !dbg !45
  ret i32 0, !dbg !46
}

attributes #0 = { noinline nounwind uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { nounwind allocsize(0) "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { nounwind "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #4 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #5 = { nounwind allocsize(0) }
attributes #6 = { nounwind }

!llvm.dbg.cu = !{!12}
!llvm.module.flags = !{!16, !17, !18, !19, !20, !21, !22}
!llvm.ident = !{!23}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(scope: null, file: !2, line: 12, type: !3, isLocal: true, isDefinition: true)
!2 = !DIFile(filename: "test_files/test_05_cwe476.c", directory: "/home/manavtejani/Desktop/Academics/Automata/VulnHGNN", checksumkind: CSK_MD5, checksum: "44d11f50226c47807b15f51054d2cb79")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 96, elements: !5)
!4 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!5 = !{!6}
!6 = !DISubrange(count: 12)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(scope: null, file: !2, line: 13, type: !9, isLocal: true, isDefinition: true)
!9 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 144, elements: !10)
!10 = !{!11}
!11 = !DISubrange(count: 18)
!12 = distinct !DICompileUnit(language: DW_LANG_C11, file: !2, producer: "Ubuntu clang version 18.1.3 (1ubuntu1)", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, retainedTypes: !13, globals: !15, splitDebugInlining: false, nameTableKind: None)
!13 = !{!14}
!14 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!15 = !{!0, !7}
!16 = !{i32 7, !"Dwarf Version", i32 5}
!17 = !{i32 2, !"Debug Info Version", i32 3}
!18 = !{i32 1, !"wchar_size", i32 4}
!19 = !{i32 8, !"PIC Level", i32 2}
!20 = !{i32 7, !"PIE Level", i32 2}
!21 = !{i32 7, !"uwtable", i32 2}
!22 = !{i32 7, !"frame-pointer", i32 2}
!23 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
!24 = distinct !DISubprogram(name: "handle_record", scope: !2, file: !2, line: 9, type: !25, scopeLine: 9, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !12, retainedNodes: !28)
!25 = !DISubroutineType(types: !26)
!26 = !{null, !27}
!27 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!28 = !{}
!29 = !DILocalVariable(name: "id", arg: 1, scope: !24, file: !2, line: 9, type: !27)
!30 = !DILocation(line: 9, column: 24, scope: !24)
!31 = !DILocalVariable(name: "name", scope: !24, file: !2, line: 10, type: !14)
!32 = !DILocation(line: 10, column: 11, scope: !24)
!33 = !DILocation(line: 10, column: 26, scope: !24)
!34 = !DILocation(line: 12, column: 12, scope: !24)
!35 = !DILocation(line: 12, column: 5, scope: !24)
!36 = !DILocation(line: 13, column: 34, scope: !24)
!37 = !DILocation(line: 13, column: 38, scope: !24)
!38 = !DILocation(line: 13, column: 5, scope: !24)
!39 = !DILocation(line: 14, column: 10, scope: !24)
!40 = !DILocation(line: 14, column: 5, scope: !24)
!41 = !DILocation(line: 15, column: 1, scope: !24)
!42 = distinct !DISubprogram(name: "main", scope: !2, file: !2, line: 17, type: !43, scopeLine: 17, spFlags: DISPFlagDefinition, unit: !12)
!43 = !DISubroutineType(types: !44)
!44 = !{!27}
!45 = !DILocation(line: 18, column: 5, scope: !42)
!46 = !DILocation(line: 19, column: 5, scope: !42)
