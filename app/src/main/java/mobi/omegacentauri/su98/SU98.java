package mobi.omegacentauri.su98;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.AssetManager;
import android.icu.util.Output;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.util.Log;
import android.view.View;
import android.widget.CheckBox;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class SU98 extends Activity {

    private String myDir;
    private String su;
    static final String ONBOOT_INSTALL = "onBoot";
    private SharedPreferences options;
    private CheckBox boot;
    private TextView messages;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        options = PreferenceManager.getDefaultSharedPreferences(this);
        setContentView(R.layout.activity_su98);
        messages = findViewById(R.id.state);

        myDir = getApplicationInfo().dataDir+"/";
        su = myDir + "su98";

        install(this, myDir);
    }

    public static boolean install(Context c, String myDir) {
        if (! copyAssetToFile(c,"su98", myDir + "su98", true) ) {
            Toast.makeText(c, "Cannot install su98 into "+myDir, Toast.LENGTH_LONG).show();
            return false;
        }
        if (! copyAssetToFile(c, "install.sh", myDir + "install.sh", true) ) {
            Toast.makeText(c, "Cannot install install.sh into "+myDir, Toast.LENGTH_LONG).show();
            return false;
        }
        if (! copyAssetToFile(c,"uninstall.sh", myDir + "uninstall.sh", true) ) {
            Toast.makeText(c, "Cannot install install.sh into "+myDir, Toast.LENGTH_LONG).show();
            return false;
        }
        return true;
    }

    boolean checkState() {
        return new File("/sbin/su98").exists();
    }

    boolean updateState() {
        if (checkState()) {
            messages.append("Current status: /sbin/su98 installed\n");
            return true;
        }
        else {
            messages.append("Current status: /sbin/su98 not installed\n");
            return false;
        }
    }

    @Override
    protected void onResume() {
        super.onResume();

        updateState();

        boot = (CheckBox)findViewById(R.id.install_boot);

        boot.setChecked(options.getBoolean(ONBOOT_INSTALL,false ));
    }

    private static boolean copyAssetToFile(Context c, String source, String target, boolean executable) {
        new File(target).delete();
        InputStream src = null;
        FileOutputStream dest = null;
        try {
            src = c.getAssets().open(source);
            dest = new FileOutputStream(target);
            byte[] buffer = new byte[1024];
            do {
                int r = src.read(buffer);
                if (r <= 0)
                    break;
                dest.write(buffer, 0, r);
            } while(true);
            src.close();
            src = null;
            dest.close();
            dest = null;
            new File(target).setExecutable(true);
        } catch (IOException e) {
            Log.e("SU98", "exception", e);
            if (src != null) {
                try {
                    src.close();
                } catch (IOException e1) {
                }
            }
            if (dest != null) {
                try {
                    dest.close();
                } catch (IOException e1) {
                }
            }
            return false;
        }
        return true;
    }

    public void onInstallBootButton(View view) {
        SharedPreferences.Editor ed = options.edit();
        ed.putBoolean(ONBOOT_INSTALL, boot.isChecked());
        ed.commit();
    }

    public void onInstallButton(View view) {
        messages.append("Installing\n");
        if (Root.runOne(su, myDir + "install.sh")) {
            if (checkState())
                messages.append("Success!\n");
            else
                messages.append("Failure\n");

        }
        else {
            messages.append("Failure\n");
            Toast.makeText(this,"Install failure", Toast.LENGTH_LONG).show();
        }
        updateState();
    }

    public void onUninstallButton(View view) {
        messages.append("Uninstalling\n");
        if (Root.runOne(su, myDir + "uninstall.sh")) {
            if (! checkState())
                messages.append("Success!\n");
            else
                messages.append("Failure\n");
        }
        else {
            messages.append("Failure\n");
            Toast.makeText(this,"Uninstall failure", Toast.LENGTH_LONG).show();
        }
        messages.append("Disabling SELinux\n");
        Root.runOne(su, "setenforce 1");
        updateState();
    }
}
