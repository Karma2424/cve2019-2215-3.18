package mobi.omegacentauri.su98;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.util.Log;
import android.widget.Toast;

public class Boot extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.v("SU98", "on boot");
        SharedPreferences options = PreferenceManager.getDefaultSharedPreferences(context);
        if (!options.getBoolean(SU98.ONBOOT_INSTALL, false))
            return;

        String myDir = context.getApplicationInfo().dataDir+"/";

        SU98.install(context, myDir);
        if (Root.runOne(myDir + "su98", myDir + "install.sh")) {
            Toast.makeText(context,"su98 installed", Toast.LENGTH_LONG).show();
        }
    }
}

