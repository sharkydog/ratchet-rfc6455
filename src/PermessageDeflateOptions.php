<?php

namespace Ratchet\RFC6455\Handshake;

final class PermessageDeflateOptions
{
    const MAX_WINDOW_BITS = 15;
    /* this is a private instead of const for 5.4 compatibility */
    private static $VALID_BITS = ['8', '9', '10', '11', '12', '13', '14', '15'];

    private $deflateEnabled = false;

    private $server_no_context_takeover;
    private $client_no_context_takeover;
    private $server_max_window_bits;
    private $client_max_window_bits;

    private function __construct() { }

    public static function createEnabled() {
        $new                             = new static();
        $new->deflateEnabled             = true;
        $new->client_max_window_bits     = self::MAX_WINDOW_BITS;
        $new->client_no_context_takeover = false;
        $new->server_max_window_bits     = self::MAX_WINDOW_BITS;
        $new->server_no_context_takeover = false;

        return $new;
    }

    public static function createDisabled() {
        return new static();
    }

    public function withClientNoContextTakeover() {
        $new = clone $this;
        $new->client_no_context_takeover = true;
        return $new;
    }

    public function withoutClientNoContextTakeover() {
        $new = clone $this;
        $new->client_no_context_takeover = false;
        return $new;
    }

    public function withServerNoContextTakeover() {
        $new = clone $this;
        $new->server_no_context_takeover = true;
        return $new;
    }

    public function withoutServerNoContextTakeover() {
        $new = clone $this;
        $new->server_no_context_takeover = false;
        return $new;
    }

    public function withServerMaxWindowBits($bits = self::MAX_WINDOW_BITS) {
        if (!in_array($bits, self::$VALID_BITS)) {
            throw new \Exception('server_max_window_bits must have a value between 8 and 15.');
        }
        $new = clone $this;
        $new->server_max_window_bits = $bits;
        return $new;
    }

    public function withClientMaxWindowBits($bits = self::MAX_WINDOW_BITS) {
        if (!in_array($bits, self::$VALID_BITS)) {
            throw new \Exception('client_max_window_bits must have a value between 8 and 15.');
        }
        $new = clone $this;
        $new->client_max_window_bits = $bits;
        return $new;
    }

    /**
     * @return mixed
     */
    public function getServerNoContextTakeover()
    {
        return $this->server_no_context_takeover;
    }

    /**
     * @return mixed
     */
    public function getClientNoContextTakeover()
    {
        return $this->client_no_context_takeover;
    }

    /**
     * @return mixed
     */
    public function getServerMaxWindowBits()
    {
        return $this->server_max_window_bits;
    }

    /**
     * @return mixed
     */
    public function getClientMaxWindowBits()
    {
        return $this->client_max_window_bits;
    }

    /**
     * @return bool
     */
    public function isEnabled()
    {
        return $this->deflateEnabled;
    }

    public static function permessageDeflateSupported($version = PHP_VERSION) {
        if (!function_exists('deflate_init')) {
            return false;
        }
        if (version_compare($version, '7.1.3', '>')) {
            return true;
        }
        if (version_compare($version, '7.0.18', '>=')
            && version_compare($version, '7.1.0', '<')) {
            return true;
        }

        return false;
    }

    public static function fromHeader($header) {
        $deflate = static::createDisabled();

        if(empty($header=array_filter(array_map('trim',explode(',',$header))))) {
            return $deflate;
        }

        foreach($header as $ext) {
            if(strpos($ext=strtolower($ext),'permessage-deflate')!==0) {
                continue;
            }
            $deflate = static::createEnabled();
            break;
        }

        if(!$deflate->isEnabled()) {
            return $deflate;
        }

        // 19 = strlen('permessage-deflate;')
        $ext = array_filter(array_map('trim',explode(';',substr($ext,19))));

        // ['a','b=','c=cc'] -> ['a'=>true, 'b'=>true, 'c'=>'cc']
        $k=[];
        array_walk($ext, function(&$v) use(&$k) {
            $o = array_filter(array_map('trim',explode('=',$v,2)));
            $k[] = $o[0];
            $v = !empty($o[1]) ? $o[1] : true;
        });
        $ext = array_combine($k,$ext);

        if(isset($ext['client_no_context_takeover'])) {
            $deflate = $deflate->withClientNoContextTakeover();
        }
        if(isset($ext['server_no_context_takeover'])) {
            $deflate = $deflate->withServerNoContextTakeover();
        }
        if(!empty($ext['client_max_window_bits'])) {
            $deflate = $deflate->withClientMaxWindowBits($ext['client_max_window_bits']);
        }
        if(!empty($ext['server_max_window_bits'])) {
            $deflate = $deflate->withServerMaxWindowBits($ext['server_max_window_bits']);
        }

        return $deflate;
    }
    
    public function renderHeader() {
        if(!$this->isEnabled()) return '';

        $header  = 'permessage-deflate';

        if(($b=$this->getClientMaxWindowBits()) != 15) {
            $header .= '; client_max_window_bits='.$b;
        }
        if(($b=$this->getServerMaxWindowBits()) != 15) {
            $header .= '; server_max_window_bits='.$b;
        }

        if($this->getClientNoContextTakeover()) {
            $header .= '; client_no_context_takeover';
        }
        if($this->getServerNoContextTakeover()) {
            $header .= '; server_no_context_takeover';
        }

        return $header;
    }
}
