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
    this.buffer = buf;
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
}

function parse(buf){
    var dns = new dnspacket(buf);
    dns.parse_header();

    console.log(dns);
}





/* example code*/
var d = new dns({
    question:{
        name:'jsmean.com'
    }
});
const dgram = require('dgram');
const message = d.getBuffer();
const client = dgram.createSocket('udp4');
client.on('message',(msg)=>{
    console.log(msg);
    parse(msg);
    client.close();
})

client.send(message, 53, '1.2.4.8', (err) => {
  if(err){
      console.log(err);
  }
});