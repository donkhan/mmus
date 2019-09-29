package controllers;

import com.google.gson.JsonObject;
import play.*;
import play.mvc.*;

import java.util.*;

import models.*;
import play.Logger;
import play.libs.WS;

public class Application extends Controller {

    public static void index() {
        render();
    }


    public static void invokeWorkFlow() {
        Logger.debug("Workflow Invoked from " + request);
        String url = "http://maxmoney.com/handle-gopay.php";
        Logger.debug("PHP URL %s",url);
        JsonObject content = new JsonObject();
        content.addProperty("umobileclienttoken","test");
        content.addProperty("testproperty","xyz");
        Logger.debug("Content " + content);
        WS.HttpResponse response = WS.url(url).body(content).post();


    }

}