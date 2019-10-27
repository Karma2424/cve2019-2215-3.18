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

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        options = PreferenceManager.getDefaultSharedPreferences(this);
        setContentView(R.layout.activity_su98);

        myDir = getApplicationInfo().dataDir+"/";
        su = myDir + "su98" + " -n";

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

    boolean updateState() {
        TextView tv = findViewById(R.id.state);
        if (new File("/sbin/su98").exists()) {
            tv.setText("Current status: /sbin/su98 installed");
            return true;
        }
        else {
            tv.setText("Current status: /sbin/su98 not installed");
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
        Toast.makeText(this,"Installing", Toast.LENGTH_LONG).show();
        if (Root.runOne(su, myDir + "install.sh")) {
            if (updateState())
                Toast.makeText(this,"Successful installation", Toast.LENGTH_LONG).show();
        }
        else {
            Toast.makeText(this,"Install failure", Toast.LENGTH_LONG).show();
        }
    }

    public void onUninstallButton(View view) {
        Toast.makeText(this,"Uninstalling", Toast.LENGTH_LONG).show();
        if (Root.runOne(su, myDir + "uninstall.sh")) {
            if (! updateState())
                Toast.makeText(this,"Successful uninstallation", Toast.LENGTH_LONG).show();
        }
        else {
            Toast.makeText(this,"Uninstall failure", Toast.LENGTH_LONG).show();
        }
        Toast.makeText(this,"Enabling SELinux", Toast.LENGTH_LONG).show();
        Root.runOne(su, "setenforce 1");
    }
}
