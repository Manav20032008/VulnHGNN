; ModuleID = 'test_files/test_10_all_vulnerabilities.c'
source_filename = "test_files/test_10_all_vulnerabilities.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [24 x i8] c"V1: %d, V2: %d, V3: %d\0A\00", align 1, !dbg !0

; Function Attrs: noinline nounwind uwtable
define dso_local void @the_ultimate_test(i32 noundef %0, i32 noundef %1, i32 noundef %2) #0 !dbg !20 {
  %4 = alloca i32, align 4
  %5 = alloca i32, align 4
  %6 = alloca i32, align 4
  %7 = alloca ptr, align 8
  %8 = alloca i32, align 4
  %9 = alloca i32, align 4
  %10 = alloca i32, align 4
  store i32 %0, ptr %4, align 4
  call void @llvm.dbg.declare(metadata ptr %4, metadata !24, metadata !DIExpression()), !dbg !25
  store i32 %1, ptr %5, align 4
  call void @llvm.dbg.declare(metadata ptr %5, metadata !26, metadata !DIExpression()), !dbg !27
  store i32 %2, ptr %6, align 4
  call void @llvm.dbg.declare(metadata ptr %6, metadata !28, metadata !DIExpression()), !dbg !29
  call void @llvm.dbg.declare(metadata ptr %7, metadata !30, metadata !DIExpression()), !dbg !31
  %11 = call noalias ptr @malloc(i64 noundef 4) #5, !dbg !32
  store ptr %11, ptr %7, align 8, !dbg !31
  %12 = load i32, ptr %4, align 4, !dbg !33
  %13 = load ptr, ptr %7, align 8, !dbg !34
  store i32 %12, ptr %13, align 4, !dbg !35
  call void @llvm.dbg.declare(metadata ptr %8, metadata !36, metadata !DIExpression()), !dbg !37
  %14 = load ptr, ptr %7, align 8, !dbg !38
  %15 = load i32, ptr %14, align 4, !dbg !39
  %16 = add nsw i32 %15, 2147483647, !dbg !40
  store i32 %16, ptr %8, align 4, !dbg !37
  call void @llvm.dbg.declare(metadata ptr %9, metadata !41, metadata !DIExpression()), !dbg !42
  %17 = load i32, ptr %5, align 4, !dbg !43
  %18 = sub nsw i32 %17, 2000000, !dbg !44
  store i32 %18, ptr %9, align 4, !dbg !42
  call void @llvm.dbg.declare(metadata ptr %10, metadata !45, metadata !DIExpression()), !dbg !46
  %19 = load i32, ptr %8, align 4, !dbg !47
  %20 = load i32, ptr %6, align 4, !dbg !48
  %21 = sdiv i32 %19, %20, !dbg !49
  store i32 %21, ptr %10, align 4, !dbg !46
  %22 = load i32, ptr %8, align 4, !dbg !50
  %23 = load i32, ptr %9, align 4, !dbg !51
  %24 = load i32, ptr %10, align 4, !dbg !52
  %25 = call i32 (ptr, ...) @printf(ptr noundef @.str, i32 noundef %22, i32 noundef %23, i32 noundef %24), !dbg !53
  %26 = load ptr, ptr %7, align 8, !dbg !54
  call void @free(ptr noundef %26) #6, !dbg !55
  ret void, !dbg !56
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: nounwind allocsize(0)
declare noalias ptr @malloc(i64 noundef) #2

declare i32 @printf(ptr noundef, ...) #3

; Function Attrs: nounwind
declare void @free(ptr noundef) #4

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @main() #0 !dbg !57 {
  %1 = alloca i32, align 4
  store i32 0, ptr %1, align 4
  call void @the_ultimate_test(i32 noundef 100, i32 noundef -2147483548, i32 noundef 0), !dbg !60
  ret i32 0, !dbg !61
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
!1 = distinct !DIGlobalVariable(scope: null, file: !2, line: 24, type: !3, isLocal: true, isDefinition: true)
!2 = !DIFile(filename: "test_files/test_10_all_vulnerabilities.c", directory: "/home/manavtejani/Desktop/Academics/Automata/VulnHGNN", checksumkind: CSK_MD5, checksum: "07c69c24d9db33abd9c782482b5d0bc3")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 192, elements: !5)
!4 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!5 = !{!6}
!6 = !DISubrange(count: 24)
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
!20 = distinct !DISubprogram(name: "the_ultimate_test", scope: !2, file: !2, line: 9, type: !21, scopeLine: 9, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !7, retainedNodes: !23)
!21 = !DISubroutineType(types: !22)
!22 = !{null, !10, !10, !10}
!23 = !{}
!24 = !DILocalVariable(name: "a", arg: 1, scope: !20, file: !2, line: 9, type: !10)
!25 = !DILocation(line: 9, column: 28, scope: !20)
!26 = !DILocalVariable(name: "b", arg: 2, scope: !20, file: !2, line: 9, type: !10)
!27 = !DILocation(line: 9, column: 35, scope: !20)
!28 = !DILocalVariable(name: "c", arg: 3, scope: !20, file: !2, line: 9, type: !10)
!29 = !DILocation(line: 9, column: 42, scope: !20)
!30 = !DILocalVariable(name: "p", scope: !20, file: !2, line: 10, type: !9)
!31 = !DILocation(line: 10, column: 10, scope: !20)
!32 = !DILocation(line: 10, column: 21, scope: !20)
!33 = !DILocation(line: 13, column: 10, scope: !20)
!34 = !DILocation(line: 13, column: 6, scope: !20)
!35 = !DILocation(line: 13, column: 8, scope: !20)
!36 = !DILocalVariable(name: "v1", scope: !20, file: !2, line: 16, type: !10)
!37 = !DILocation(line: 16, column: 9, scope: !20)
!38 = !DILocation(line: 16, column: 16, scope: !20)
!39 = !DILocation(line: 16, column: 15, scope: !20)
!40 = !DILocation(line: 16, column: 19, scope: !20)
!41 = !DILocalVariable(name: "v2", scope: !20, file: !2, line: 19, type: !10)
!42 = !DILocation(line: 19, column: 9, scope: !20)
!43 = !DILocation(line: 19, column: 14, scope: !20)
!44 = !DILocation(line: 19, column: 16, scope: !20)
!45 = !DILocalVariable(name: "v3", scope: !20, file: !2, line: 22, type: !10)
!46 = !DILocation(line: 22, column: 9, scope: !20)
!47 = !DILocation(line: 22, column: 14, scope: !20)
!48 = !DILocation(line: 22, column: 19, scope: !20)
!49 = !DILocation(line: 22, column: 17, scope: !20)
!50 = !DILocation(line: 24, column: 40, scope: !20)
!51 = !DILocation(line: 24, column: 44, scope: !20)
!52 = !DILocation(line: 24, column: 48, scope: !20)
!53 = !DILocation(line: 24, column: 5, scope: !20)
!54 = !DILocation(line: 25, column: 10, scope: !20)
!55 = !DILocation(line: 25, column: 5, scope: !20)
!56 = !DILocation(line: 26, column: 1, scope: !20)
!57 = distinct !DISubprogram(name: "main", scope: !2, file: !2, line: 28, type: !58, scopeLine: 28, spFlags: DISPFlagDefinition, unit: !7)
!58 = !DISubroutineType(types: !59)
!59 = !{!10}
!60 = !DILocation(line: 29, column: 5, scope: !57)
!61 = !DILocation(line: 30, column: 5, scope: !57)
