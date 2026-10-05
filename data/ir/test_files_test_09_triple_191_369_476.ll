; ModuleID = 'test_files/test_09_triple_191_369_476.c'
source_filename = "test_files/test_09_triple_191_369_476.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [12 x i8] c"Result: %d\0A\00", align 1, !dbg !0

; Function Attrs: noinline nounwind uwtable
define dso_local void @risky_logic(i32 noundef %0, i32 noundef %1) #0 !dbg !20 {
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  %6 = alloca i32, align 4
  %7 = alloca i32, align 4
  store i32 %0, ptr %3, align 4
  call void @llvm.dbg.declare(metadata ptr %3, metadata !24, metadata !DIExpression()), !dbg !25
  store i32 %1, ptr %4, align 4
  call void @llvm.dbg.declare(metadata ptr %4, metadata !26, metadata !DIExpression()), !dbg !27
  call void @llvm.dbg.declare(metadata ptr %5, metadata !28, metadata !DIExpression()), !dbg !29
  %8 = call noalias ptr @malloc(i64 noundef 4) #5, !dbg !30
  store ptr %8, ptr %5, align 8, !dbg !29
  %9 = load i32, ptr %3, align 4, !dbg !31
  %10 = load ptr, ptr %5, align 8, !dbg !32
  store i32 %9, ptr %10, align 4, !dbg !33
  call void @llvm.dbg.declare(metadata ptr %6, metadata !34, metadata !DIExpression()), !dbg !35
  %11 = load ptr, ptr %5, align 8, !dbg !36
  %12 = load i32, ptr %11, align 4, !dbg !37
  %13 = sub nsw i32 %12, 2147483647, !dbg !38
  store i32 %13, ptr %6, align 4, !dbg !35
  call void @llvm.dbg.declare(metadata ptr %7, metadata !39, metadata !DIExpression()), !dbg !40
  %14 = load i32, ptr %6, align 4, !dbg !41
  %15 = load i32, ptr %4, align 4, !dbg !42
  %16 = sdiv i32 %14, %15, !dbg !43
  store i32 %16, ptr %7, align 4, !dbg !40
  %17 = load i32, ptr %7, align 4, !dbg !44
  %18 = call i32 (ptr, ...) @printf(ptr noundef @.str, i32 noundef %17), !dbg !45
  %19 = load ptr, ptr %5, align 8, !dbg !46
  call void @free(ptr noundef %19) #6, !dbg !47
  ret void, !dbg !48
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: nounwind allocsize(0)
declare noalias ptr @malloc(i64 noundef) #2

declare i32 @printf(ptr noundef, ...) #3

; Function Attrs: nounwind
declare void @free(ptr noundef) #4

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @main() #0 !dbg !49 {
  %1 = alloca i32, align 4
  store i32 0, ptr %1, align 4
  call void @risky_logic(i32 noundef 10, i32 noundef 0), !dbg !52
  ret i32 0, !dbg !53
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
!1 = distinct !DIGlobalVariable(scope: null, file: !2, line: 21, type: !3, isLocal: true, isDefinition: true)
!2 = !DIFile(filename: "test_files/test_09_triple_191_369_476.c", directory: "/home/manavtejani/Desktop/Academics/Automata/VulnHGNN", checksumkind: CSK_MD5, checksum: "fe045fb3309dee5417bc9e21b383dec6")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 96, elements: !5)
!4 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!5 = !{!6}
!6 = !DISubrange(count: 12)
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
!20 = distinct !DISubprogram(name: "risky_logic", scope: !2, file: !2, line: 9, type: !21, scopeLine: 9, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !7, retainedNodes: !23)
!21 = !DISubroutineType(types: !22)
!22 = !{null, !10, !10}
!23 = !{}
!24 = !DILocalVariable(name: "val", arg: 1, scope: !20, file: !2, line: 9, type: !10)
!25 = !DILocation(line: 9, column: 22, scope: !20)
!26 = !DILocalVariable(name: "div", arg: 2, scope: !20, file: !2, line: 9, type: !10)
!27 = !DILocation(line: 9, column: 31, scope: !20)
!28 = !DILocalVariable(name: "ptr", scope: !20, file: !2, line: 10, type: !9)
!29 = !DILocation(line: 10, column: 10, scope: !20)
!30 = !DILocation(line: 10, column: 23, scope: !20)
!31 = !DILocation(line: 13, column: 12, scope: !20)
!32 = !DILocation(line: 13, column: 6, scope: !20)
!33 = !DILocation(line: 13, column: 10, scope: !20)
!34 = !DILocalVariable(name: "sub", scope: !20, file: !2, line: 16, type: !10)
!35 = !DILocation(line: 16, column: 9, scope: !20)
!36 = !DILocation(line: 16, column: 16, scope: !20)
!37 = !DILocation(line: 16, column: 15, scope: !20)
!38 = !DILocation(line: 16, column: 20, scope: !20)
!39 = !DILocalVariable(name: "result", scope: !20, file: !2, line: 19, type: !10)
!40 = !DILocation(line: 19, column: 9, scope: !20)
!41 = !DILocation(line: 19, column: 18, scope: !20)
!42 = !DILocation(line: 19, column: 24, scope: !20)
!43 = !DILocation(line: 19, column: 22, scope: !20)
!44 = !DILocation(line: 21, column: 28, scope: !20)
!45 = !DILocation(line: 21, column: 5, scope: !20)
!46 = !DILocation(line: 22, column: 10, scope: !20)
!47 = !DILocation(line: 22, column: 5, scope: !20)
!48 = !DILocation(line: 23, column: 1, scope: !20)
!49 = distinct !DISubprogram(name: "main", scope: !2, file: !2, line: 25, type: !50, scopeLine: 25, spFlags: DISPFlagDefinition, unit: !7)
!50 = !DISubroutineType(types: !51)
!51 = !{!10}
!52 = !DILocation(line: 26, column: 5, scope: !49)
!53 = !DILocation(line: 27, column: 5, scope: !49)
