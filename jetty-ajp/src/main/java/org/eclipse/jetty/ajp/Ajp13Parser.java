//
//  ========================================================================
//  Copyright (c) 1995-2014 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.eclipse.jetty.ajp;

import java.io.IOException;
import java.io.InterruptedIOException;

import javax.servlet.ServletInputStream;

import org.eclipse.jetty.http.HttpTokens;
import org.eclipse.jetty.http.Parser;
import org.eclipse.jetty.io.Buffer;
import org.eclipse.jetty.io.BufferUtil;
import org.eclipse.jetty.io.Buffers;
import org.eclipse.jetty.io.ByteArrayBuffer;
import org.eclipse.jetty.io.EndPoint;
import org.eclipse.jetty.io.EofException;
import org.eclipse.jetty.io.View;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;

/**
 * 
 */
public class Ajp13Parser implements Parser
{
    private static final Logger LOG = Log.getLogger(Ajp13Parser.class);

    private final static int STATE_START = -1;
    private final static int STATE_END = 0;
    private final static int STATE_AJP13CHUNK = 1;

    private int _state = STATE_START;
    private long _contentLength;
    private long _contentPosition;
    private Buffers _buffers;
    private EndPoint _endp;
    private Buffer _header; // Buffer for header data
    private Buffer _body; // Buffer for large content
    private ByteArrayBuffer _lowBuffer = new ByteArrayBuffer(Ajp13Packet.MAX_PACKET_SIZE);
    private View _contentView = new View();
    private EventHandler _handler;
    private Ajp13Generator _generator;
    private View _tok0; // Saved token: header name, request method or response version
    private View _tok1; // Saved token: header value, request URI orresponse code
    private int _packetLength;
    private boolean _firstBody = true;

    /* ------------------------------------------------------------------------------- */
    public Ajp13Parser(Buffers buffers, EndPoint endPoint)
    {
        _buffers = buffers;
        _endp = endPoint;
    }
    
    /* ------------------------------------------------------------------------------- */
    public void setEventHandler(EventHandler handler)
    {
        _handler=handler;
    }
    
    /* ------------------------------------------------------------------------------- */
    public void setGenerator(Ajp13Generator generator)
    {
        _generator=generator;
    }

    /* ------------------------------------------------------------------------------- */
    public long getContentLength()
    {
        return _contentLength;
    }

    /* ------------------------------------------------------------------------------- */
    public int getState()
    {
        return _state;
    }

    /* ------------------------------------------------------------------------------- */
    public boolean inContentState()
    {
        return _state > 0;
    }

    /* ------------------------------------------------------------------------------- */
    public boolean inHeaderState()
    {
        return _state < 0;
    }

    /* ------------------------------------------------------------------------------- */
    public boolean isIdle()
    {
        return _state == STATE_START;
    }

    /* ------------------------------------------------------------------------------- */
    public boolean isComplete()
    {
        return _state == STATE_END;
    }

    /* ------------------------------------------------------------------------------- */
    public boolean isMoreInBuffer()
    {

        if (_header != null && _header.hasContent() || _body != null && _body.hasContent())
            return true;

        return false;
    }

    /* ------------------------------------------------------------------------------- */
    public boolean isState(int state)
    {
        return _state == state;
    }

    /* ------------------------------------------------------------------------------- */
    public void parse() throws IOException
    {
        if (_state == STATE_END)
            reset();
        if (_state != STATE_START)
            throw new IllegalStateException("!START");

        // continue parsing
        while (!isComplete())
        {
            parseNext();
        }
    }

    /* ------------------------------------------------------------------------------- */
    public boolean parseAvailable() throws IOException
    {
        boolean progress=parseNext()>0;
        
        // continue parsing
        while (!isComplete() && haveContent())
        {
            progress |= parseNext()>0;
        }
        return progress;
    }

    private boolean haveContent()
    {
        if(_state==STATE_START)
        {
            return (_header!=null && _header.length()>0);
        }
        if(_state==STATE_AJP13CHUNK)
        {
            return (_body!=null && _body.length()>0);
        }
        return false;
    }

    /* ------------------------------------------------------------------------------- */
    private int fill(Buffer bf, int size) throws IOException
    {
        if (bf.putIndex() == bf.capacity())
        {
            throw new IOException("FULL");
        }
        if(bf.space()<size)
        {
            throw new IOException("not enough space, expect " + size + ", but only " + bf.space());
        }

        int filled = 0;
        if (_endp != null)
        {
            while(filled < size)
            {
                // read from low endpoint
                if(_lowBuffer.length() <= 0)
                {
                    _lowBuffer.clear();
                    int got = 0;
                    try
                    {
                        got = _endp.fill(_lowBuffer);
                    }
                    catch(IOException e)
                    {
                        if(filled > 0)
                        {
                            LOG.info("Error reading data after "+filled+"bytes", e);
                        }
                        else
                        {
                            LOG.debug("Error reading data", e);
                        }
                        reset();
                        throw (e instanceof EofException) ? e : new EofException(e);
                    }
                    if(got<0)
                    {
                        // This happens periodically, as apache restarts periodically.
                        if(filled > 0)
                        {
                            LOG.info("EOF reached after "+filled+"bytes");
                        }
                        else
                        {
                            LOG.debug("EOF reached");
                        }
                        reset();
                        return got;
                    }
                }

                // copy bytes to bf
                if(_lowBuffer.length()>0)
                {
                    int copy = _lowBuffer.length();
                    if(copy > (size-filled)){
                        copy = size - filled;
                    }
                    bf.put(_lowBuffer.array(), _lowBuffer.getIndex(), copy);
                    _lowBuffer.skip(copy);
                    filled = filled + copy;
                }
            }
        }

        return filled;
    }

    private void printStatus(String msg){
        StringBuilder sb = new StringBuilder();

        sb.append("Thread=").append(Thread.currentThread().getName()).append(",");

        if(msg!=null)
        {
            sb.append(msg).append(",");
        }

        sb.append("status=");
        if(this._state==STATE_START)
        {
            sb.append("STATE_START");
        }
        else if(this._state==STATE_END)
        {
            sb.append("STATE_END");
        }
        else if(this._state==STATE_AJP13CHUNK)
        {
            sb.append("STATE_AJP13CHUNK");
        }
        sb.append(",");

        sb.append("header=");
        if(this._header==null)
        {
            sb.append("null");
        }
        else
        {
            sb.append(this._header.length());
        }
        sb.append(",");

        sb.append("body=");
        if(this._body==null)
        {
            sb.append("null");
        }
        else
        {
            sb.append(this._body.length());
        }
        sb.append(",");

        sb.append("low=").append(this._lowBuffer.length());

        LOG.debug(sb.toString());
    }

    /* ------------------------------------------------------------------------------- */
    public int parseNext() throws IOException
    {
        if(_state==STATE_START)
        {
            return this.parseServerPacket();
        }

        if(_state==STATE_END)
        {
            throw new IllegalStateException("STATE_END");
        }

        if(_state==STATE_AJP13CHUNK)
        {
            return this.parseBodyPacket();
        }

        throw new IllegalStateException("unknown STATE: " + _state);
    }

    private int parseServerPacket() throws IOException {
        int total_filled = 0;

        // init buffer
        if(_header==null)
        {
            _header = _buffers.getBuffer();
        }
        if(_body==null)
        {
            _body = _buffers.getBuffer();
        }
        _tok0 = new View(_header);
        _tok1 = new View(_header);
        _tok0.setPutIndex(_tok0.getIndex());
        _tok1.setPutIndex(_tok1.getIndex());
        _contentLength = HttpTokens.UNKNOWN_CONTENT;

        total_filled = this.readOnePacket(_header);
        if(total_filled<0)
        {
            // remote connection closed
            return -1;
        }

        // Parse Header
        Buffer bufHeaderName = null;
        Buffer bufHeaderValue = null;
        int attr_type = 0;

        byte packetType = Ajp13RequestPacket.getByte(_header);

        switch (packetType)
        {
            case Ajp13Packet.FORWARD_REQUEST_ORDINAL:
                _handler.startForwardRequest();
                break;
            case Ajp13Packet.CPING_REQUEST_ORDINAL:
                _generator.sendCPong();
                reset();
                return -1;
            case Ajp13Packet.SHUTDOWN_ORDINAL:
                shutdownRequest();
                return -1;
            default:
                // XXX Throw an Exception here?? Close
                // connection!
                LOG.warn("AJP13 message type ({PING}: "+packetType+" ) not supported/recognized as an AJP request");
                throw new IllegalStateException("PING is not implemented");
        }

        _handler.parsedMethod(Ajp13RequestPacket.getMethod(_header));
        _handler.parsedProtocol(Ajp13RequestPacket.getString(_header, _tok0));
        _handler.parsedUri(Ajp13RequestPacket.getString(_header, _tok1));
        _handler.parsedRemoteAddr(Ajp13RequestPacket.getString(_header, _tok1));
        _handler.parsedRemoteHost(Ajp13RequestPacket.getString(_header, _tok1));
        _handler.parsedServerName(Ajp13RequestPacket.getString(_header, _tok1));
        _handler.parsedServerPort(Ajp13RequestPacket.getInt(_header));
        _handler.parsedSslSecure(Ajp13RequestPacket.getBool(_header));

        int headers = Ajp13RequestPacket.getInt(_header);
        for (int h=0;h<headers;h++)
        {
            bufHeaderName = Ajp13RequestPacket.getHeaderName(_header, _tok0);
            bufHeaderValue = Ajp13RequestPacket.getString(_header, _tok1);

            if (bufHeaderName != null && bufHeaderName.toString().equals(Ajp13RequestHeaders.CONTENT_LENGTH))
            {
                _contentLength = BufferUtil.toLong(bufHeaderValue);
                if (_contentLength == 0)
                {
                    _contentLength = HttpTokens.NO_CONTENT;
                }
            }

            _handler.parsedHeader(bufHeaderName, bufHeaderValue);
        }

        attr_type = Ajp13RequestPacket.getByte(_header) & 0xff;
        while (attr_type != 0xFF)
        {
            switch (attr_type)
            {
                // XXX How does this plug into the web
                // containers
                // authentication?

                case Ajp13RequestHeaders.REMOTE_USER_ATTR:
                    _handler.parsedRemoteUser(Ajp13RequestPacket.getString(_header, _tok1));
                    break;
                case Ajp13RequestHeaders.AUTH_TYPE_ATTR:
                    //XXX JASPI how does this make sense?
                    _handler.parsedAuthorizationType(Ajp13RequestPacket.getString(_header, _tok1));
                    break;

                case Ajp13RequestHeaders.QUERY_STRING_ATTR:
                    _handler.parsedQueryString(Ajp13RequestPacket.getString(_header, _tok1));
                    break;

                case Ajp13RequestHeaders.JVM_ROUTE_ATTR:
                    // moved to Eclipse naming usage
                    // used in org.eclipse.jetty.servlet.HashSessionIdManager
                    _handler.parsedRequestAttribute("org.eclipse.jetty.ajp.JVMRoute", Ajp13RequestPacket.getString(_header, _tok1));
                    break;

                case Ajp13RequestHeaders.SSL_CERT_ATTR:
                    _handler.parsedSslCert(Ajp13RequestPacket.getString(_header, _tok1));
                    break;

                case Ajp13RequestHeaders.SSL_CIPHER_ATTR:
                    _handler.parsedSslCipher(Ajp13RequestPacket.getString(_header, _tok1));
                    // SslSocketConnector.customize()
                    break;

                case Ajp13RequestHeaders.SSL_SESSION_ATTR:
                    _handler.parsedSslSession(Ajp13RequestPacket.getString(_header, _tok1));
                    break;

                case Ajp13RequestHeaders.REQUEST_ATTR:
                    _handler.parsedRequestAttribute(Ajp13RequestPacket.getString(_header, _tok0).toString(), Ajp13RequestPacket.getString(_header, _tok1));
                    break;

                    // New Jk API?
                    // Check if experimental or can they
                    // assumed to be
                    // supported
                    
                case Ajp13RequestHeaders.SSL_KEYSIZE_ATTR:
                    
                    // This has been implemented in AJP13 as either a string or a integer.
                    // Servlet specs say javax.servlet.request.key_size must be an Integer
                    
                    // Does it look like a string containing digits?
                    int length = Ajp13RequestPacket.getInt(_header);
                    
                    if (length>0 && length<16)
                    {
                        // this must be a string length rather than a key length
                        _header.skip(-2);
                        _handler.parsedSslKeySize(Integer.parseInt(Ajp13RequestPacket.getString(_header, _tok1).toString()));
                    }
                    else
                        _handler.parsedSslKeySize(length);
                    
                    break;

                    
                    // Used to lock down jk requests with a
                    // secreate
                    // key.
                    
                case Ajp13RequestHeaders.SECRET_ATTR:
                    // XXX Investigate safest way to
                    // deal with
                    // this...
                    // should this tie into shutdown
                    // packet?
                    break;

                case Ajp13RequestHeaders.STORED_METHOD_ATTR:
                    // XXX Confirm this should
                    // really overide
                    // previously parsed method?
                    // _handler.parsedMethod(Ajp13PacketMethods.CACHE.get(Ajp13RequestPacket.getString()));
                    break;

                case Ajp13RequestHeaders.CONTEXT_ATTR:
                    _handler.parsedContextPath(Ajp13RequestPacket.getString(_header, _tok1));
                    break;
                case Ajp13RequestHeaders.SERVLET_PATH_ATTR:
                    _handler.parsedServletPath(Ajp13RequestPacket.getString(_header, _tok1));

                    break;
                default:
                    LOG.warn("Unsupported Ajp13 Request Attribute {}", new Integer(attr_type));
                    break;
            }

            attr_type = Ajp13RequestPacket.getByte(_header) & 0xff;
        }

        _contentPosition = 0;
        switch ((int) _contentLength)
        {
            case HttpTokens.NO_CONTENT:
                _state = STATE_END;
                _handler.headerComplete();
                _handler.messageComplete(_contentPosition);
                break;

            case HttpTokens.UNKNOWN_CONTENT:
                _state = STATE_AJP13CHUNK;
                _handler.headerComplete(); // May recurse here!
                break;

            default:
                _state = STATE_AJP13CHUNK;
                _handler.headerComplete(); // May recurse here!
                break;
        }

        return total_filled;
    }

    private int parseBodyPacket() throws IOException {
        if (_contentPosition == _contentLength)
        {
            _state = STATE_END;
            _handler.messageComplete(_contentPosition);
            return 1;
        }

        int total_filled = 0;

        if(_firstBody)
        {
            _firstBody = false;
        }
        else
        {
            _generator.getBodyChunk();
        }

        // read one packet
        _body.clear();
        total_filled = this.readOnePacket(_body);
        if(total_filled<0)
        {
            // remote connection closed
            return -1;
        }

        // No data received. just the header
        if(_packetLength<=0)
        {
            _state=STATE_END;
            _generator.gotBody();
           _handler.messageComplete(_contentPosition);
           return total_filled;
        }

        // in ajp13 protocol, next 2 bytes is dataLength
        // also equal to '_packetLength -2'
        int dataLength = _packetLength - 2;
        if(dataLength<=0)
        {
            _state=STATE_END;
            _generator.gotBody();
           _handler.messageComplete(_contentPosition);
           return total_filled;
        }

        Buffer chunk = Ajp13RequestPacket.get(_body, dataLength);
        _contentPosition+=chunk.length();
        _contentView.update(chunk);

        if (_contentPosition>=_contentLength)
        {
            _generator.gotBody();
        }
        _handler.content(chunk);

        return total_filled;
    }

    private int readOnePacket(Buffer bf) throws IOException
    {
        int total_filled = fill(bf, 4);
        if(total_filled<0)
        {
            return total_filled;
        }
        int _magic = Ajp13RequestPacket.getInt(bf);
        if (_magic != Ajp13RequestHeaders.MAGIC)
        {
            throw new IOException("Bad AJP13 rcv packet: " + "0x" + Integer.toHexString(_magic) + " expected " + "0x" + Integer.toHexString(Ajp13RequestHeaders.MAGIC) + " " + this);
        }
        _packetLength = Ajp13RequestPacket.getInt(bf);
        if (_packetLength > Ajp13Packet.MAX_PACKET_SIZE)
        {
            throw new IOException("AJP13 packet (" + _packetLength + "bytes) too large for buffer");
        }
        int filled = fill(bf, _packetLength);
        if(filled<0)
        {
            return filled;
        }

        total_filled += filled;
        if(LOG.isDebugEnabled())
        {
            this.printStatus("read:" + total_filled);
        }

        return total_filled;
    }

    /* ------------------------------------------------------------------------------- */
    public void reset()
    {
        _state = STATE_START;
        _contentLength = HttpTokens.UNKNOWN_CONTENT;
        _contentPosition = 0;
        _firstBody = true;

        if (_header != null) {
            _header.setPutIndex(0);
            _header.setGetIndex(0);
            _header.setMarkIndex(-1);
        }

        if (_body != null) {
            _body.setPutIndex(0);
            _body.setGetIndex(0);
            _body.setMarkIndex(-1);
        }

        if(LOG.isDebugEnabled())
        {
            this.printStatus("reset");
        }
    }

    /* ------------------------------------------------------------------------------- */
    public void returnBuffers()
    {
        if (_buffers != null)
        {
            if(_body != null)
            {
                _buffers.returnBuffer(_body);
                _body = null;
            }

            if(_header != null)
            {
                _buffers.returnBuffer(_header);
                _header = null;
            }
        }
    }

    /* ------------------------------------------------------------------------------- */
    private void shutdownRequest()
    {
        _state = STATE_END;

        if(!Ajp13SocketConnector.__allowShutdown)
        {
            LOG.warn("AJP13: Shutdown Request is Denied, allowShutdown is set to false!!!");
            return;
        }

        if(Ajp13SocketConnector.__secretWord != null)
        {
            LOG.warn("AJP13: Validating Secret Word");
            try
            {
                String secretWord = Ajp13RequestPacket.getString(_header, _tok1).toString();

                if(!Ajp13SocketConnector.__secretWord.equals(secretWord))
                {
                    LOG.warn("AJP13: Shutdown Request Denied, Invalid Sercret word!!!");
                    throw new IllegalStateException("AJP13: Secret Word is Invalid: Peer has requested shutdown but, Secret Word did not match");
                }
            }
            catch (Exception e)
            {
                LOG.warn("AJP13: Secret Word is Required!!!");
                LOG.debug(e);
                throw new IllegalStateException("AJP13: Secret Word is Required: Peer has requested shutdown but, has not provided a Secret Word");
            }


            LOG.warn("AJP13: Shutdown Request is Denied, allowShutdown is set to false!!!");
            return;
        }

        LOG.warn("AJP13: Peer Has Requested for Shutdown!!!");
        LOG.warn("AJP13: Jetty 6 is shutting down !!!");
        System.exit(0);
    }

    /* ------------------------------------------------------------------------------- */
    public interface EventHandler
    {

        // public void shutdownRequest() throws IOException;
        // public void cpingRequest() throws IOException;

        public void content(Buffer ref) throws IOException;

        public void headerComplete() throws IOException;

        public void messageComplete(long contextLength) throws IOException;

        public void parsedHeader(Buffer name, Buffer value) throws IOException;

        public void parsedMethod(Buffer method) throws IOException;

        public void parsedProtocol(Buffer protocol) throws IOException;

        public void parsedQueryString(Buffer value) throws IOException;

        public void parsedRemoteAddr(Buffer addr) throws IOException;

        public void parsedRemoteHost(Buffer host) throws IOException;

        public void parsedRequestAttribute(String key, Buffer value) throws IOException;
        
        public void parsedRequestAttribute(String key, int value) throws IOException;

        public void parsedServerName(Buffer name) throws IOException;

        public void parsedServerPort(int port) throws IOException;

        public void parsedSslSecure(boolean secure) throws IOException;

        public void parsedUri(Buffer uri) throws IOException;

        public void startForwardRequest() throws IOException;

        public void parsedAuthorizationType(Buffer authType) throws IOException;
        
        public void parsedRemoteUser(Buffer remoteUser) throws IOException;

        public void parsedServletPath(Buffer servletPath) throws IOException;
        
        public void parsedContextPath(Buffer context) throws IOException;

        public void parsedSslCert(Buffer sslCert) throws IOException;

        public void parsedSslCipher(Buffer sslCipher) throws IOException;

        public void parsedSslSession(Buffer sslSession) throws IOException;

        public void parsedSslKeySize(int keySize) throws IOException;





    }

    /* ------------------------------------------------------------ */
    /**
     * TODO Make this common with HttpParser
     * 
     */
    public static class Input extends ServletInputStream
    {
        private Ajp13Parser _parser;
        private EndPoint _endp;
        private long _maxIdleTime;
        private View _content;

        /* ------------------------------------------------------------ */
        public Input(Ajp13Parser parser, long maxIdleTime)
        {
            _parser = parser;
            _endp = parser._endp;
            _maxIdleTime = maxIdleTime;
            _content = _parser._contentView;
        }

        /* ------------------------------------------------------------ */
        @Override
        public int read() throws IOException
        {
            int c = -1;
            if (blockForContent())
                c = 0xff & _content.get();
            return c;
        }

        /* ------------------------------------------------------------ */
        /*
         * @see java.io.InputStream#read(byte[], int, int)
         */
        @Override
        public int read(byte[] b, int off, int len) throws IOException
        {
            int l = -1;
            if (blockForContent())
                l = _content.get(b, off, len);
            return l;
        }

        /* ------------------------------------------------------------ */
        private boolean blockForContent() throws IOException
        {
            if (_content.length() > 0)
                return true;
            if (_parser.isState(Ajp13Parser.STATE_END) || _parser.isState(Ajp13Parser.STATE_START))
                return false;

            // Handle simple end points.
            if (_endp == null)
                _parser.parseNext();

            // Handle blocking end points
            else if (_endp.isBlocking())
            {
                _parser.parseNext();
                
                // parse until some progress is made (or IOException thrown for timeout)
                while (_content.length() == 0 && _parser.isState(Ajp13Parser.STATE_AJP13CHUNK))
                {
                    // Try to get more _parser._content
                    _parser.parseNext();
                }
            }
            else // Handle non-blocking end point
            {
                long filled = _parser.parseNext();
                boolean blocked = false;

                // parse until some progress is made (or
                // IOException thrown for timeout)
                while (_content.length() == 0 && _parser.isState(Ajp13Parser.STATE_AJP13CHUNK))
                {
                    // if fill called, but no bytes read,
                    // then block
                    if (filled > 0)
                        blocked = false;
                    else if (filled == 0)
                    {
                        if (blocked)
                            throw new InterruptedIOException("timeout");

                        blocked = true;
                        _endp.blockReadable(_maxIdleTime);
                    }

                    // Try to get more _parser._content
                    filled = _parser.parseNext();
                }
            }

            return _content.length() > 0;
        }
    }

    public boolean isPersistent()
    {
        return true;
    }

    public void setPersistent(boolean persistent)
    {
        LOG.warn("AJP13.setPersistent is not IMPLEMENTED!");
    }
}
