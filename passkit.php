<?php
class passKit{
    protected $certPath;// 签名证书路径
    protected $wwdrPath;// WWDR证书路径
    protected $certPassword = "";// 签名证书密码
    protected $passDir;// 卡包模板路径
    protected $tempPath;// 可读可写的临时文件目录
    public $passkit = [];

    /*
    * 传入卡包预制模板的路径，需包含pass.json文件
    */
    public function __construct(String $dir){
        try{
            $this->passDir = realpath($dir) . "/";
            $passfile = file_get_contents($this->passDir . "pass.json");
            $this->passkit = json_decode($passfile,true);
        }catch(Exception $e){
            return $e->getMessage();
        }
    }

    public function setCert($path){ // 设置签名证书路径
        $this->certPath = $path;
    }

    public function setWWDR($path){ // 设置WWDR证书路径
        $this->wwdrPath = $path;
    }

    public function setPassword($password){ // 设置证书密码
        $this->certPassword = $password;
    }

    /*
    * 向用户生成好的pkpass文件
    */
    public function outputPass(){
        if(is_array($this->passkit))
            return false;
        header('Content-Type: application/vnd.apple.pkpass');
        header('Content-Disposition: attachment; filename="pass.pkpass"');
        header('Content-Transfer-Encoding: binary');
        header('Connection: Keep-Alive');
        header('Expires: 0');
        echo $this->passkit;
    }

    /*
    * 返回生成的pkpass文件
    */
    public function exportPass(){
        $mainfest = [];
        $this->getTempDir();
        $this->passkit = json_encode($this->passkit,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
        foreach(scandir($this->passDir) as $file)
            if(is_file($this->passDir.$file) && $file != "pass.json")
                $mainfest[$file] = sha1_file($this->passDir.$file);
        $mainfest["pass.json"] = sha1($this->passkit);
        $this->signPass($mainfest);
        $zip = new \ZipArchive;
        $zip->open($this->tempPath."pass.pkpass", \ZipArchive::CREATE | \ZipArchive::OVERWRITE);
        foreach(scandir($this->passDir) as $file)
            if(is_file($this->passDir.$file) && $file != "pass.json")
                $zip->addFile($this->passDir.$file,$file);
        $zip->addFile($this->tempPath."manifest.json","manifest.json");
        $zip->addFile($this->tempPath."signature","signature");
        $zip-close();
        $this->passkit = file_get_contents($this->tempPath."pass.pkpass")
        return $this->passkit;
    }

    /*
    * 对mainfest进行签名
    */
    private function signPass(Array $mainfest){
        $certs = [];
        file_put_contents($this->tempPath."manifest.json",json_encode($mainfest,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
        try{
            openssl_pkcs12_read(file_get_contents($this->certPath), $certs, $this->$certPassword);
            $openssl_args = [
                $this->tempPath."manifest.json",
                $this->tempPath."signature",
                openssl_x509_read($certs['cert']),
                openssl_pkey_get_private($certs['pkey'], $this->$certPassword),
                [],
                PKCS7_BINARY | PKCS7_DETACHED,
                $this->wwdrPath
            ];
            call_user_func_array('openssl_pkcs7_sign', $openssl_args);
        }catch(Exception $e){
            return $e->getMessage();
        }
        if(!is_file($this->tempPath."signature"))
            return false;
        $signature = file_get_contents($this->tempPath."signature");
        $begin = 'filename="smime.p7s"';
        $end = '------';
        $signature = substr($signature, strpos($signature, $begin) + strlen($begin));
        $signature = substr($signature, 0, strpos($signature, $end));
        $signature = trim($signature);
        $signature = base64_decode($signature);
        file_put_contents($this->tempPath."signature", $signature);
        return true;
    }

    /*
    * 提供一个可用的临时目录
    */
    private function setTempDir(){
        $dir = sys_get_temp_dir() . '/passkit/';
        if(!is_dir($dir))
            mkdir($dir,0777);
        $this->tempPath = $dir;
        return true;
    }
}
