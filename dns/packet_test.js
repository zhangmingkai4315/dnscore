const dgram = require('dgram');
const mocha = require('mocha');  //eslint-disable-line
const expect = require('expect');
const dns_const = require('./dns_const');
const dns_packet = require('./packet');
const DNS_SERVER = '1.2.4.8';
/* example code*/
var client;
/* eslint-disable no-undef */
describe('server', function () {
    before(function () {
        client = dgram.createSocket('udp4');
    });
    afterEach(function(){
        client.removeAllListeners('message');
    });
    it('should get A record',function(done){
        var d = new dns_packet.dns({
            question:{
                name:'jsmean.com', //chinatesters.cn
                type:dns_const.QUERY.A
            }
        });
        client.on('message',(msg)=>{
            var p = dns_packet.parse(msg); 
            expect(p.answer.length).toEqual(1);
            expect(p.answer[0].data).toEqual('139.162.118.119');
            expect(p.answer[0].domain).toEqual('jsmean.com.');
            expect(p.answer[0].type).toEqual(dns_const.QUERY.A);
            done();
        });
        client.send(d.getBuffer(), 53, DNS_SERVER, (err) => {
            if(err){
                done(err);
            }
        });
    });
    it('should get NS record',function(done){
        var d = new dns_packet.dns({
            question:{
                name:'jsmean.com', //chinatesters.cn
                type:dns_const.QUERY.NS
            }
        });
        client.on('message',(msg)=>{
            var p = dns_packet.parse(msg); 
            expect(p.answer.length).toEqual(2);
            expect(p.answer[0].domain).toEqual('jsmean.com.');
            expect(p.answer[1].domain).toEqual('jsmean.com.');
            expect(p.answer[0].data).toInclude('.domaincontrol.com.');
            expect(p.answer[1].data).toInclude('.domaincontrol.com.');
            done();
        });
        client.send(d.getBuffer(), 53, DNS_SERVER, (err) => {
            if(err){
                done(err);
            }
        });
    });

    it('should get SOA record',function(done){
        var d = new dns_packet.dns({
            question:{
                name:'jsmean.com', //chinatesters.cn
                type:dns_const.QUERY.SOA
            }
        });
        client.on('message',(msg)=>{
            var p = dns_packet.parse(msg); 
            expect(p.answer.length).toEqual(1);
            expect(p.answer[0].data).toExist();
            expect(p.answer[0].data.expire).toExist();
            expect(p.answer[0].data.minTTL).toExist();
            expect(p.answer[0].data.refresh).toExist();
            expect(p.answer[0].data.retry).toExist();
            expect(p.answer[0].data.mail).toExist();
            expect(p.answer[0].data.serial).toExist();
            expect(p.answer[0].domain).toEqual('jsmean.com.');
            done();
        });
        client.send(d.getBuffer(), 53, DNS_SERVER, (err) => {
            if(err){
                done(err);
            }
        });
    });
    it('should get AAAA record',function(done){
        var d = new dns_packet.dns({
            question:{
                name:'google.com', //chinatesters.cn
                type:dns_const.QUERY.AAAA
            }
        });
        client.on('message',(msg)=>{
            var p = dns_packet.parse(msg); 
            expect(p.answer.length).toEqual(1);
            expect(p.answer[0].data).toExist();
            expect(p.answer[0].domain).toEqual('google.com.');
            // 2404:6800:4008:800:0:0:0:200e
            expect(p.answer[0].data.split(':').length===8).toEqual(true);
            done();
        });
        client.send(d.getBuffer(), 53, DNS_SERVER, (err) => {
            if(err){
                done(err);
            }
        });
    });

    it('should get TXT record',function(done){
        var d = new dns_packet.dns({
            question:{
                name:'google.com', //chinatesters.cn
                type:dns_const.QUERY.TXT
            }
        });
        client.on('message',(msg)=>{
            var p = dns_packet.parse(msg); 
            expect(p.answer.length).toEqual(1);
            expect(p.answer[0].data).toExist();
            expect(p.answer[0].domain).toEqual('google.com.');
            expect(p.answer[0].data).toEqual('v=spf1 include:_spf.google.com ~all');
            done();
        });
        client.send(d.getBuffer(), 53, DNS_SERVER, (err) => {
            if(err){
                done(err);
            }
        });
    });

    it('should get SOA record when the domain name has not txt record',function(done){
        var d = new dns_packet.dns({
            question:{
                name:'jsmean.com', //chinatesters.cn
                type:dns_const.QUERY.TXT
            }
        });
        client.on('message',(msg)=>{
            var p = dns_packet.parse(msg); 
            expect(p.answer.length).toEqual(0);
            expect(p.authority.length).toEqual(1);
            expect(p.authority[0].data).toExist();
            expect(p.authority[0].data.expire).toExist();
            expect(p.authority[0].data.minTTL).toExist();
            expect(p.authority[0].data.refresh).toExist();
            expect(p.authority[0].data.retry).toExist();
            expect(p.authority[0].data.mail).toExist();
            expect(p.authority[0].data.serial).toExist();
            expect(p.authority[0].domain).toEqual('jsmean.com.');        
            done();
        });
        client.send(d.getBuffer(), 53, DNS_SERVER, (err) => {
            if(err){
                done(err);
            }
        });
    });
    after(function () {
        client.close();
    });
});



