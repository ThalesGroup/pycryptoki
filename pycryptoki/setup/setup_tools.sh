
if [ $# -ne 2 ]
  then
    echo "ERROR: No username and password specified to access gccxml source code from the wiki. Argument 1 must be the username to the safenet wiki, Argument 2 must be the password to the safenet wiki."
    echo "Example ./setup_tools.sh mhughes mypassword"
    exit -1
fi
#Set up CMake
wget http://www.cmake.org/files/v2.8/cmake-2.8.8.tar.gz
tar -xzvf cmake-2.8.8.tar.gz
cd cmake-2.8.8
./configure
gmake
gmake install
cd ..

#Set up gcc-xml
wget http://mysno/Personal/amer_pohalloran/KnowledgeBaseWiki/Files/gccxml.tar.gz --user=$1 --password=$2
tar -xzvf gccxml.tar.gz
cd gccxml
find . -name *.* \ tr -d '\r'
cd ..
mkdir gccxml-build
cd gccxml-build
../cmake-2.8.8/bin/cmake ../gccxml -DCMAKE_INSTALL_PREFIX:PATH=.
make
make install

#Update the user's path
cd bin
export PATH=$PATH:$PWD
echo "export PATH=\$PATH:${PWD}" >> ~/.bashrc
