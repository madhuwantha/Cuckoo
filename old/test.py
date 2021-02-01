import pexpect

 

def __main():
    
    try:
        var_password  = "1234"
        var_command = "scp -o StrictHostKeychecking=no dev1.csv fyp@192.168.8.103:/home/fyp/"
        #make sure in the above command that username and hostname are according to your server
        var_child = pexpect.spawn(var_command)
        i = var_child.expect(["password:"])
        print(i)

        if i==0: # send password                
                var_child.sendline(var_password)
                var_child.expect(pexpect.EOF)
        elif i==1: 
                print("Got the key or connection timeout")
                pass

    except Exception as e:
        print("Oops Something went wrong buddy")
        print(e)

if __name__ == '__main__':
    __main()
