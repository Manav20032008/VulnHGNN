; ModuleID = 'test_files/test_08_triple_190_191_369.c'
source_filename = "test_files/test_08_triple_190_191_369.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [10 x i8] c"%d %d %d\0A\00", align 1, !dbg !0

; Function Attrs: noinline nounwind uwtable
define dso_local void @math_chaos(i32 noundef %0, i32 noundef %1, i32 noundef %2) #0 !dbg !17 {
  %4 = alloca i32, align 4
  %5 = alloca i32, align 4
  %6 = alloca i32, align 4
  %7 = alloca i32, align 4
  %8 = alloca i32, align 4
  %9 = alloca i32, align 4
  store i32 %0, ptr %4, align 4
  call void @llvm.dbg.declare(metadata ptr %4, metadata !22, metadata !DIExpression()), !dbg !23
  store i32 %1, ptr %5, align 4
  call void @llvm.dbg.declare(metadata ptr %5, metadata !24, metadata !DIExpression()), !dbg !25
  store i32 %2, ptr %6, align 4
  call void @llvm.dbg.declare(metadata ptr %6, metadata !26, metadata !DIExpression()), !dbg !27
  call void @llvm.dbg.declare(metadata ptr %7, metadata !28, metadata !DIExpression()), !dbg !29
  %10 = load i32, ptr %4, align 4, !dbg !30
  %11 = add nsw i32 %10, 1000000, !dbg !31
  store i32 %11, ptr %7, align 4, !dbg !29
  call void @llvm.dbg.declare(metadata ptr %8, metadata !32, metadata !DIExpression()), !dbg !33
  %12 = load i32, ptr %5, align 4, !dbg !34
  %13 = sub nsw i32 %12, 1000000, !dbg !35
  store i32 %13, ptr %8, align 4, !dbg !33
  call void @llvm.dbg.declare(metadata ptr %9, metadata !36, metadata !DIExpression()), !dbg !37
  %14 = load i32, ptr %7, align 4, !dbg !38
  %15 = load i32, ptr %6, align 4, !dbg !39
  %16 = sdiv i32 %14, %15, !dbg !40
  store i32 %16, ptr %9, align 4, !dbg !37
  %17 = load i32, ptr %7, align 4, !dbg !41
  %18 = load i32, ptr %8, align 4, !dbg !42
  %19 = load i32, ptr %9, align 4, !dbg !43
  %20 = call i32 (ptr, ...) @printf(ptr noundef @.str, i32 noundef %17, i32 noundef %18, i32 noundef %19), !dbg !44
  ret void, !dbg !45
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

declare i32 @printf(ptr noundef, ...) #2

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @main() #0 !dbg !46 {
  %1 = alloca i32, align 4
  store i32 0, ptr %1, align 4
  call void @math_chaos(i32 noundef 2147483637, i32 noundef -2147483638, i32 noundef 0), !dbg !49
  ret i32 0, !dbg !50
}

attributes #0 = { noinline nounwind uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.dbg.cu = !{!7}
!llvm.module.flags = !{!9, !10, !11, !12, !13, !14, !15}
!llvm.ident = !{!16}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(scope: null, file: !2, line: 18, type: !3, isLocal: true, isDefinition: true)
!2 = !DIFile(filename: "test_files/test_08_triple_190_191_369.c", directory: "/home/manavtejani/Desktop/Academics/Automata/VulnHGNN", checksumkind: CSK_MD5, checksum: "ccfaa260723667bc4cdec67a9237dd01")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 80, elements: !5)
!4 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!5 = !{!6}
!6 = !DISubrange(count: 10)
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
!17 = distinct !DISubprogram(name: "math_chaos", scope: !2, file: !2, line: 8, type: !18, scopeLine: 8, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !7, retainedNodes: !21)
!18 = !DISubroutineType(types: !19)
!19 = !{null, !20, !20, !20}
!20 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!21 = !{}
!22 = !DILocalVariable(name: "a", arg: 1, scope: !17, file: !2, line: 8, type: !20)
!23 = !DILocation(line: 8, column: 21, scope: !17)
!24 = !DILocalVariable(name: "b", arg: 2, scope: !17, file: !2, line: 8, type: !20)
!25 = !DILocation(line: 8, column: 28, scope: !17)
!26 = !DILocalVariable(name: "c", arg: 3, scope: !17, file: !2, line: 8, type: !20)
!27 = !DILocation(line: 8, column: 35, scope: !17)
!28 = !DILocalVariable(name: "v1", scope: !17, file: !2, line: 10, type: !20)
!29 = !DILocation(line: 10, column: 9, scope: !17)
!30 = !DILocation(line: 10, column: 14, scope: !17)
!31 = !DILocation(line: 10, column: 16, scope: !17)
!32 = !DILocalVariable(name: "v2", scope: !17, file: !2, line: 13, type: !20)
!33 = !DILocation(line: 13, column: 9, scope: !17)
!34 = !DILocation(line: 13, column: 14, scope: !17)
!35 = !DILocation(line: 13, column: 16, scope: !17)
!36 = !DILocalVariable(name: "v3", scope: !17, file: !2, line: 16, type: !20)
!37 = !DILocation(line: 16, column: 9, scope: !17)
!38 = !DILocation(line: 16, column: 14, scope: !17)
!39 = !DILocation(line: 16, column: 19, scope: !17)
!40 = !DILocation(line: 16, column: 17, scope: !17)
!41 = !DILocation(line: 18, column: 26, scope: !17)
!42 = !DILocation(line: 18, column: 30, scope: !17)
!43 = !DILocation(line: 18, column: 34, scope: !17)
!44 = !DILocation(line: 18, column: 5, scope: !17)
!45 = !DILocation(line: 19, column: 1, scope: !17)
!46 = distinct !DISubprogram(name: "main", scope: !2, file: !2, line: 21, type: !47, scopeLine: 21, spFlags: DISPFlagDefinition, unit: !7)
!47 = !DISubroutineType(types: !48)
!48 = !{!20}
!49 = !DILocation(line: 22, column: 5, scope: !46)
!50 = !DILocation(line: 23, column: 5, scope: !46)
