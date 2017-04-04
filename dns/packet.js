const dns_const = require('./dns_const');

const defaultOption={
    rd:dns_const.RD_DESIRED,
    question:{
        type:dns_const.QUERY.A,
        name:dns_const.ROOT
    }
}

/**
 * @constructor query dns packet
 * @param {object} option (default query '.' and type 'A')
 */
function dns(option){
    if(!option){
        option=defaultOption;
    }else{
        option=Object.assign({},defaultOption,option)
    }
    this.offset = 0
    this.buffer = Buffer.allocUnsafe(512);
    this.offset = dns_header(this.buffer,this.offset,option);
    this.offset= dns_question(this.buffer,this.offset,option);
    return this;
}

/**
 * @description return the buffer with a new header.
 * @param {Buffer} buf
 * @param {number} offset
 * @param {object} option
 * @returns {Buffer} 
 */
function dns_header(buf,offset,option){
    buf.writeUInt16BE(Math.floor(Math.random() * Math.pow(2,16)),offset)
    var flag = option.rd === dns_const.RD_DESIRED? 1<<8 : 0 
    buf.writeUInt16BE(flag,offset+2);
    buf.writeUInt16BE(1,offset+4);
    buf.writeUInt16BE(0,offset+6);
    buf.writeUInt16BE(0,offset+8);
    buf.writeUInt16BE(0,offset+10);
    return offset+12;
}

/**
 * @description return the buffer with a new questions zone.
 * @param {Buffer} buf
 * @param {number} offset
 * @param {object} option
 * @returns {Buffer} 
 */
function dns_question(buf,offset,option){
    var type = option.question.type||dns_const.QUERY.A;
    var name = option.question.name||dns_const.ROOT;
    var classin =option.question.class||dns_const.CLASS_IN;
    for(var subdomain of name.split('.')){
      if(subdomain!==''){
        var domainlength=subdomain.length;
        buf.writeUInt16BE(domainlength<<8,offset);
        offset=offset+1;
        buf.write(subdomain,offset,domainlength,'ascii');
        offset+=subdomain.length;
      }
    }
    buf.writeUInt16BE(0x00&0xFFFF,offset);
    offset=offset+1
    buf.writeUInt16BE(type&0xFFFF,offset);
    offset=offset+2
    buf.writeUInt16BE(classin&0xFFFF,offset);
    return offset+2;
}


/**
 * @description return the buffer
 * @returns {Buffer}
 */
dns.prototype.getBuffer = function(){
    return this.buffer.slice(0,this.offset);
}

/* Unpack the dns buffer to a object */ 


/**
 * A dns packet for hold all the infomation.
 * @constructor
 * @param {Buffer} buf
 * @returns {Object} this
 */

function dnspacket(buf){
    /* buffer from socket */ 
    this.buffer = buf;
    /* offset for read buf */ 
    this.offset = 0;
    /* cache for message compression */ 
    this.cache ={

    }
    this.header = {  
    }
    this.question = [];
    this.answer = [];
    this.authority = [];
    this.additional = [];
    return this;
}
/**
 * @description parse the socket raw buffer and return a parsed dns object.
 * @param {Buffer} buf
 * @returns {dnspacket} dns
 */
function parse(buf){
    var dns = new dnspacket(buf);
    dns.parse_header();
    dns.parse_question();
    dns.parse_zones();
    // delete dns.cache
    // delete dns.buffer
    // delete dns.offset
    return dns
}
/**
 * @description parse the raw buffer and retrive the dns header information.
 * @param 
 * @returns
 */
dnspacket.prototype.parse_header=function(){
    this.header.id = this.buffer.readUInt16BE(0);
    let val = this.buffer.readUInt16BE(2);
    this.header.qr = val>> 15;
    this.header.opcode = (val & 0x7800) >> 11;
    this.header.aa = (val & 0x400) >> 10;
    this.header.tc = (val & 0x200) >> 9;
    this.header.rd = (val & 0x100) >> 8;
    this.header.ra = (val & 0x80) >> 7;
    this.header.rcode = (val & 0xF);
    this.question.length= this.buffer.readUInt16BE(4);
    this.answer.length =this.buffer.readUInt16BE(6);
    this.authority.length = this.buffer.readUInt16BE(8);
    this.additional.length =this.buffer.readUInt16BE(10);
    this.offset = 12;
}

/**
 * @description parse the raw buffer and retrive the dns questions information.
 * @param 
 * @returns
 */
dnspacket.prototype.parse_question=function(){
    var len = this.question.length;
    if(len===0){
        return
    }
    for(var i=0;i<len;i++){
        var offset = this.offset;
        var domainName=''
        var readlen= this.buffer.readUIntBE(offset,1);
        var recorder = '';
        var keyList = [];
        while(readlen){      
            recorder = this.buffer.toString('ascii',offset+1,readlen+offset+1)+'.'
            domainName+=recorder;
            this.cache[offset]=recorder;
            for(var i of keyList){
                this.cache[i]=this.cache[i]+recorder;
            }
            keyList.push(offset);
            offset = readlen+offset+1;
            readlen = this.buffer.readUIntBE(offset,1);
        }
        
        var type = this.buffer.readUInt16BE(offset+1);
        var classin = this.buffer.readUInt16BE(offset+3);
        this.question.shift()
        this.question.push({domain:domainName,type:type,class:classin});
        this.offset=offset+5
    }
}

/**
 * @description parse the raw buffer and retrive the dns (answer,authority,additional) information.
 * @param 
 * @returns
 */
dnspacket.prototype.parse_zones=function(){
    for(var zone of [this.answer,this.authority,this.additional]){
        var len =zone.length;
        if(len===0){
            return
        }
        for(var i=0;i<len;i++){
            var domainName=this._getDomainName(this.buffer.slice(this.offset),1)
            var offset = this.offset;
            var type = this.buffer.readUInt16BE(offset);
            var classin = this.buffer.readUInt16BE(offset+2);
            var ttl =  this.buffer.readUInt32BE(offset+4);
            var length =  this.buffer.readUInt16BE(offset+8);
            var data =  this.buffer.slice(offset+10,offset+10+length);
            
            this.offset=offset+10
            zone.shift()
            zone.push({domain:domainName,type:type,class:classin,ttl:ttl,length:length,data:this.parseType(type,data)});
            
        }
    }
}

/**
 * @description parse the raw buffer and domain name string(compressed pointer will be replaced with original string).
 * @param {Buffer} data
 * @param {number} max_pointers，you can define with only one pointer limit to use in response packet parse.
 * @returns {string} domainName
 */
dnspacket.prototype._getDomainName=function(data,max_pointers){
            var offset = 0;
            var beginPoint = this.offset;
            var domainName=''
            var readlen= data.readUIntBE(offset,1);
            var recorder = '';
            var keyList = [];
            var cache=[];
            var pointerCounter = 0;
            while(readlen){
                if(readlen>64){
                    var _p= data.readUInt16BE(offset);
                    pointer = _p&0x03fff
                    recorder=this.cache[pointer]
                    offset+=2;
                    cache[this.offset+offset]=recorder;
                    pointerCounter++;

                }else{
                    recorder = data.toString('ascii',offset+1,readlen+offset+1)+'.';
                    // cache[this.offset+offset]=recorder;
                    keyList.push(this.offset+offset);
                    offset=offset+readlen+1;
                }
                domainName+=recorder;
                for(var i of keyList){
                    cache[i]=(cache[i]||'')+recorder;
                }
                if(offset >= data.length){
                    break;
                }
                if(max_pointers&&pointerCounter===max_pointers){
                    break;
                }
                readlen = data.readUIntBE(offset,1);
            }
            this.cache=Object.assign({},this.cache,cache);
            this.offset = this.offset+offset;
            return domainName
}

/**
 * @description parse the raw buffer based its type.
 * @param {string} type , all type will be included in dns_const.QUERY.
 * @param {Buffer} data the orignal part of buffer. 
 * @returns {string|object} based the different type will return different object or string
 * For example: if type === dns_const.QUERY.A  and a ip string will be returned. but if type === dns_const.QUERY.MX, 
 * a object {preference:10,exchange:'mx.example.com'} will be returned
 */
dnspacket.prototype.parseType=function(type,data){
    switch(type){
        case dns_const.QUERY.A:{
            return this.parse_A(data);
        }
        case dns_const.QUERY.NS:{
            return this.parse_NS(data);
        }
        case dns_const.QUERY.TXT:{
            return this.parse_TXT(data);
        }
        case dns_const.QUERY.MX:{
            return this.parse_MX(data);
        }
        case dns_const.QUERY.AAAA:{
            return this.parse_AAAA(data);
        }
        case dns_const.QUERY.SOA:{
            return this.parse_SOA(data);
        }
        case dns_const.QUERY.CAA:{
            return this.parse_CAA(data);
        }
        default:
            this.offset+=data.length;
            return data.toString('ascii');
        }
}

/**
 * @description parse the raw buffer return A record.
 * @param {Buffer} data
 * @returns {string} a IPv4 Address record
 */
dnspacket.prototype.parse_A=function(data){
    var ip = []
    for(var i=0;i<4;i++){
        ip.push(data.readUInt8(i))
    }
    this.offset+=4;
    return ip.join('.');
}
/**
 * @description parse the raw buffer return AAAA(IPv6) record.
 * @param {Buffer} data
 * @returns {string} a AAAA record
 */
dnspacket.prototype.parse_AAAA = function(data){
    var ipv6 = []
    for(var i=0;i<8;i++){
        ipv6.push(data.readUInt16BE(i*2).toString(16))
    }
    this.offset+=16;
    return ipv6.join(':');
}

/**
 * @description parse the raw buffer return SOA record.
 * @param {Buffer} data
 * @returns {string} a SOA object
 */
dnspacket.prototype.parse_SOA = function(data){
    var old_pointer = this.offset;
    var name = this._getDomainName(data,1);
    var mail = this._getDomainName(data.slice(this.offset-old_pointer),1);
    var left_data = data.slice(this.offset-old_pointer);
    this.offset += 20;
    var obj= {
        name,
        mail,
        serial:left_data.readInt32BE(),
        refresh:left_data.readInt32BE(4),
        retry:left_data.readInt32BE(8),
        expire:left_data.readInt32BE(12),
        minTTL:left_data.readInt32BE(16)
    }
    return obj;
}
/**
 * @description parse the raw buffer return NameServer record.
 * @param {Buffer} data
 * @returns {string} a NameServer record
 */
dnspacket.prototype.parse_NS=function(data){
    return this._getDomainName(data);
}
/**
 * @description parse the raw buffer return txt record.
 * @param {Buffer} data
 * @returns {string} a txt record
 */
dnspacket.prototype.parse_TXT = function(data){
    this.offset+=data.length;
    var txtLength = data.readUInt8(0);
    return data.toString('utf8',1,txtLength+1);
}

/**
 * @description parse the raw buffer return MX record.
 * @param {Buffer} data
 * @returns {string} a MX record
 */
dnspacket.prototype.parse_MX = function(data){
    this.offset+=2;
    return  {
        preference:data.readUInt16BE(0),
        exchange:this._getDomainName(data.slice(2))
    }
}


/**
 * @description parse the raw buffer return MX record.
 * @param {Buffer} data
 * @returns {string} a MX record
 */
dnspacket.prototype.parse_PTR = function(data){
    this.offset+=2;
    return  {
        preference:data.readUInt16BE(0),
        exchange:this._getDomainName(data.slice(2))
    }
}
/**
 * @description parse the raw buffer return CAA record.
 * @param {Buffer} data
 * @returns {string} a CAA record
 * @see {@link https://tools.ietf.org/html/rfc6844|RFC6844}
 */
dnspacket.prototype.parse_CAA = function(data){
    console.log(data);
    var flags = data.readIntBE(0,1);
    var caa_tags_length = data.readIntBE(1,1);
    var tag = data.slice(2,caa_tags_length+2).toString('utf8');
    var value = data.slice(caa_tags_length+2).toString('utf8');
    this.offset+=data.length;
    return {
        flags,
        tag,
        value,
    }
}



/* example code*/
var d = new dns({
    question:{
        name:'google.com',
        type:dns_const.QUERY.CAA
    }
});
const dgram = require('dgram');
const message = d.getBuffer();
const client = dgram.createSocket('udp4');
client.on('message',(msg)=>{
    var packet = parse(msg);
    console.log(packet);
    client.close();
})

client.send(message, 53, '1.2.4.8', (err) => {
  if(err){
      console.log(err);
  }
});