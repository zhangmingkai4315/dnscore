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
 * @description return the parsed dns packet.
 * @param {Buffer} buf
 * @returns {Object}  
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
dnspacket.prototype.parseType=function(type,data){
    switch(type){
        case dns_const.QUERY.A:{
            return this.parse_A(data);
        }
        case dns_const.QUERY.NS:{
            return this.parse_NS(data);
        }
        default:
            return '';
        }
}

dnspacket.prototype._getDomainName=function(data){
            var offset = 0;
            var beginPoint = this.offset;
            var domainName=''
            var readlen= data.readUIntBE(offset,1);
            var recorder = '';
            var keyList = [];
            var cache=[];
            while(readlen){
                if(readlen>64){
                    var _p= data.readUInt16BE(offset);
                    pointer = _p&0x03fff
                    recorder=this.cache[pointer]
                    offset+=2;
                    cache[this.offset+offset]=recorder;
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
                readlen = data.readUIntBE(offset,1);
            }
            this.cache=Object.assign({},this.cache,cache);
            this.offset = this.offset+offset;
            return domainName
}

dnspacket.prototype.parse_A=function(data){
    var ip = []
    for(var i=0;i<4;i++){
        ip.push(data.readUInt8(i))
    }
    this.offset+=4;
    return ip.join('.');
}

dnspacket.prototype.parse_NS=function(data){
    return this._getDomainName(data);
}
dnspacket.prototype.parse_zones=function(){
    for(var zone of [this.answer,this.authority,this.additional]){
        var len =zone.length;
        if(len===0){
            return
        }
        for(var i=0;i<len;i++){
            var domainName=this._getDomainName(this.buffer.slice(this.offset))
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
function parse(buf){
    var dns = new dnspacket(buf);
    dns.parse_header();
    dns.parse_question();
    dns.parse_zones();
    delete dns.cache
    return dns
}





/* example code*/
var d = new dns({
    question:{
        name:'baidu.com'
    }
});
const dgram = require('dgram');
const message = d.getBuffer();
const client = dgram.createSocket('udp4');
client.on('message',(msg)=>{
    console.log(parse(msg));
    client.close();
})

client.send(message, 53, '1.2.4.8', (err) => {
  if(err){
      console.log(err);
  }
});