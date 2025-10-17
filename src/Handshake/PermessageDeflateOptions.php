<?php

namespace Ratchet\RFC6455\Handshake;

final class PermessageDeflateOptions
{
    public const MAX_WINDOW_BITS = 15;

    private const VALID_BITS = [8, 9, 10, 11, 12, 13, 14, 15];

    private bool $deflateEnabled = false;

    private ?bool $server_no_context_takeover = null;
    private ?bool $client_no_context_takeover = null;
    private ?int $server_max_window_bits = null;
    private ?int $client_max_window_bits = null;

    private function __construct() { }

    public static function createEnabled() {
        $new                             = new self();
        $new->deflateEnabled             = true;
        $new->client_max_window_bits     = self::MAX_WINDOW_BITS;
        $new->client_no_context_takeover = false;
        $new->server_max_window_bits     = self::MAX_WINDOW_BITS;
        $new->server_no_context_takeover = false;

        return $new;
    }

    public static function createDisabled() {
        return new self();
    }

    public function withClientNoContextTakeover(): self {
        $new = clone $this;
        $new->client_no_context_takeover = true;
        return $new;
    }

    public function withoutClientNoContextTakeover(): self {
        $new = clone $this;
        $new->client_no_context_takeover = false;
        return $new;
    }

    public function withServerNoContextTakeover(): self {
        $new = clone $this;
        $new->server_no_context_takeover = true;
        return $new;
    }

    public function withoutServerNoContextTakeover(): self {
        $new = clone $this;
        $new->server_no_context_takeover = false;
        return $new;
    }

    public function withServerMaxWindowBits(int $bits = self::MAX_WINDOW_BITS): self {
        if (!in_array($bits, self::VALID_BITS)) {
            throw new \Exception('server_max_window_bits must have a value between 8 and 15.');
        }
        $new = clone $this;
        $new->server_max_window_bits = $bits;
        return $new;
    }

    public function withClientMaxWindowBits(int $bits = self::MAX_WINDOW_BITS): self {
        if (!in_array($bits, self::VALID_BITS)) {
            throw new \Exception('client_max_window_bits must have a value between 8 and 15.');
        }
        $new = clone $this;
        $new->client_max_window_bits = $bits;
        return $new;
    }

    /**
     * @return bool|null
     */
    public function getServerNoContextTakeover(): ?bool
    {
        return $this->server_no_context_takeover;
    }

    /**
     * @return bool|null
     */
    public function getClientNoContextTakeover(): ?bool
    {
        return $this->client_no_context_takeover;
    }

    /**
     * @return int|null
     */
    public function getServerMaxWindowBits(): ?int
    {
        return $this->server_max_window_bits;
    }

    /**
     * @return int|null
     */
    public function getClientMaxWindowBits(): ?int
    {
        return $this->client_max_window_bits;
    }

    /**
     * @return bool
     */
    public function isEnabled(): bool
    {
        return $this->deflateEnabled;
    }

    public static function permessageDeflateSupported(string $version = PHP_VERSION): bool {
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

    public static function fromHeader($header): self {
        $deflate = self::createDisabled();

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
    
    public function renderHeader(): string {
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
