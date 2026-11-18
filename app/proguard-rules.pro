# The gomobile AAR ships its own consumer rules; these are the same, restated in case
# the local-AAR path ever stops applying them.
-keep class go.** { *; }
-keep class nyampycore.** { *; }

# The subscription logos' SVG renderer; it reads its own classes reflectively.
-keep class com.caverock.androidsvg.** { *; }
