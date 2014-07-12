redo-ifchange $2.cpp compile
./compile $1 $2 $3
read DEP <$2.d
rm $2.d
redo-ifchange ${DEP#*:}
