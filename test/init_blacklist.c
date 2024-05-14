#include "./include/client.h"

/*populate the blacklist with some sample file/directory paths*/

int main(int argc, char** argv){
	int ret ;
	int syscall_index = 156;

	ret = syscall(syscall_index, "/home/zudelino/Musica/a.txt", 0 );
	if(ret < 0) {
		return -1;
		}
	ret = syscall(syscall_index, "/home/zudelino/Musica/asas", 0 );
	if(ret < 0) {
		return -1;
		}
	ret = syscall(syscall_index, NULL, 2 );
	if(ret < 0) {
		return -1;}
	return 0;
}