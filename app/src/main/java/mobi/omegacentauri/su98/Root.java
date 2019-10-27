package mobi.omegacentauri.su98;

import java.io.DataOutputStream;

import android.util.Log;

public class Root {
    private final String su;
    private DataOutputStream rootCommands;
    private Process rootShell;
    private static final boolean LOG_SU = false;

    public Root(String su) {
        this(su,false);
    }

    public Root(String su, boolean output) {
        this.su = su;
        try {
            if (output) {
                rootShell = Runtime.getRuntime().exec(su);
            }
            else {
                String[] cmds = { "sh", "-c",
                        LOG_SU ?
                                su + " >> /tmp/root.txt 2>> /tmp/root.txt"
                                : su + " > /dev/null 2> /dev/null"
                };
                rootShell = Runtime.getRuntime().exec(cmds);
            }

            rootCommands = new DataOutputStream(rootShell.getOutputStream());
        }
        catch (Exception e) {
            rootCommands = null;
        }
    }

    public static boolean test() {
        try {
            Process p = Runtime.getRuntime().exec("su");
            DataOutputStream out = new DataOutputStream(p.getOutputStream());
            out.close();
            if(p.waitFor() != 0) {
                return false;
            }
            return true;
        }
        catch (Exception e) {
            return false;
        }
    }

    public static boolean runOne(String su, String cmd) {
        try {
            String[] cmds = { "sh", "-c",
                    LOG_SU ?
                            su + " >> /tmp/root.txt 2>> /tmp/root.txt"
                            : su + " > /dev/null 2> /dev/null"
            };
            Process p = Runtime.getRuntime().exec(cmds);

            DataOutputStream shell = new DataOutputStream(p.getOutputStream());
            Log.v("root", cmd);
            shell.writeBytes(cmd + "\n");
            shell.close();
            if(p.waitFor() != 0) {
                return false;
            }
            return true;
        }
        catch(Exception e) {
            return false;
        }
    }

    public void close() {
        if (rootCommands != null) {
            try {
                rootCommands.close();
            }
            catch (Exception e) {
            }
            rootCommands = null;
        }
    }

    public void exec( String s ) {
        try {
            Log.v("root", s);
            rootCommands.writeBytes(s + "\n");
            rootCommands.flush();
        }
        catch (Exception e) {
            Log.e("Error executing",s);
        }
    }
}