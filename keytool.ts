var createHash = require('sha.js');

export interface Delegate {
  public sendMessage(msg:any) => bool;
  public showSAS(sas:string) => bool;
};

class Messages {
  enum Type { Hello1, Hello2, Commit, DHPart1, DHPart2, Confirm1, Confirm2,
              Conf2Ack };

  class HelloMessage {
    constructor(public type: string, public version: string, public h3: string,
                public hk: string, public clientVersion: string, public mac: string){}
  };

  class CommitMessage {
    constructor(public type: string, public h2: string, public hk: string,
                public clientVersion: string, public hvi: string,
                public mac: string){}
  };

  class DHPartMessage {
    constructor(public type: string, public h1: string, public pkey: string,
                public mac: string) {}
  };

  class ConfirmMessage {
    constructor(public type: string, public h0: string, public mac: string) {}
  };

  class ConfAckMessage {
    constructor(public type:string) {}
  };

  class Tagged {
    constructor(public type: Type,
                public value: HelloMessage|CommitMessage|DHPartMessage|ConfirmMessage);
  };
};

export class Verifier {
  // Only written by set(), after verifying the message.
  private messages_: { [Messages.Type]:Messages.Tagged };
  // Zero or 1.  role_ 0 sends Hello1.  role_ 1 sends Hello2.  Doesn't
  // determine who's sending 'Commit'.
  private role_:number;
  private ourPubKey_:string;
  private peerPubKey_:string;
  private ourHashes_:string[];
  private result_:Promise<bool>;
  private delegate_:Delegate;
  private static keyMap_ = {
    'Hello':'clientVersion,h3,hk,mac,type,version',
    'Commit':'clientVersion,h2,hk,hvi,mac,type',
    'DHPart1':'h1,mac,pkey,type',
    'DHPart2':'h1,mac,pkey,type',
    'Confirm1':'h0,mac,type',
    'Confirm2':'h0,mac,type',
    'Conf2Ack':'type'
  };
  private static prereqMap_ = {
    'Hello':[],
    'Commit':[Messages.Hello1, Messages.Hello2],
    'DHPart1':[Messages.Commit],
    'DHPart2':[Messages.DHPart1],
    'Confirm1':[Messages.DHPart2],
    'Confirm2':[Messages.Confirm1],
    'Conf2Ack':[Messages.Confirm2]
  };

  // Messages are existing messages received or sent in the
  // conversation.  Useful both for testing and for when this Verifier
  // is being created in response to a received message.
  constructor(ourPubKey: string,
              peerPubKey: string,
              delegate:Delegate);
  constructor(ourPubKey: string,
              peerPubKey: string,
              messages: {[Messages.Type]:Messages.Tagged},
              ourHashes: string[],
              role:number,
              delegate:Delegate) {
    this.ourPubKey_ = ourPubKey;
    this.peerPubKey_ = peerPubKey;
    this.delegate_ = delegate;

    if (messages === undefined) {
      // Beginning of conversation.
      this.messages_ = {};
      this.role_ = 0;
      this.ourHashes_ = this.generateHashes();
    } else {
      // Peer started conversation, or this is a resumption.
      this.messages_ = messages;
      this.role_ = role;
      this.ourHashes_ = ourHashes;
    }
  }

  private hashString(s:string) :string {
    return createHash('sha256').update(s).digest().toString('base64');
  }

  public readMessage(msg:any) {
    if (msg['type'] && this.structuralVerify(msg)) {
      var type = msg.type;
      if (type == 'Hello') {
        // Validate this Hello message.
        if (msg.clientVersion !== "0.1" || msg.version !== "1.0") {
          console.log("Invalid Hello message (versions): ", msg);
          this.resolve(false);
          return;
        }
        this.set(new Tagged(this.role_ == 0? Messages.Hello2 : Messages.Hello1,
                            new HelloMessage(msg.type, msg.version, msg.h3, msg.hk,
                                             msg.clientVersion, msg.mac)));

      } else if (type == 'Commit') {
        if (msg.clientVersion !== "0.1") {
          console.log("Invalid Commit message (clientVersion)", msg);
          this.resolve(false);
          return;
        }
        // Validate the Hello message's mac.
        var hello1 = this.messages_[Messages.Hello1].value;
        var hello2 = this.messages_[Messages.Hello2].value;
        var dhpart2 = this.messages_[Messages.DHPart2].value;
        if (hello1.mac !== this.mac(msg.h2, hello1.h3 + hello1.hk + message.clientVersion)) {
          console.log("MAC mismatch for Hello1 found. h2: ", msg.h2, " and Hello1: ", hello1);
          this.resolve(false);
          return;
        }
        // Validate that h3 is the hash of h2
        if (hello1.h3 !== this.hashString(msg.h2)) {
          console.log("Hash chain failure for h3: ", hello1.h3, " and h2: ", msg.h2);
          this.resolve(false);
          return;
        }
        // Check that the peer can be the initiato.
        if (this.role_ !== 1) {
          console.log("Currently, we only support that role 0 is initiator.");
          this.resolve(false);
          return;
        }
        // Check that hvi is correct.
        var hvi = this.hashString((dhpart2.h1 + dhpart2.pkey + dhpart2.mac) + (
          hello2.h3 + hello2.hk + hello2.mac));
        if (hvi !== msg.hvi) {
          console.log("hvi Mismatch in commit. Wanted: ", hvi, " got: ", msg);
          this.resolve(false);
          return;
        }
        this.set(new Tagged(Messages.Commit,
                            new CommitMessage(msg.type, msg.h2, msg.hk, msg.clientVersion,
                                              msg.hvi, msg.mac)));

      } else if (type == 'DHPart1') {
        // We don't have an h2 value to check the hello2 message.
        if (this.messages_[Messages.Hello2].value.hk !== this.hashString(msg.pkey)) {
          console.log("hash(pkey)/hk mismatch for DHPart1 (",msg.pkey,") vs Hello2 (",
                      this.messages_[Messages.Hello2].value.hk, ")");
          this.resolve(false);
          return;
        }

        this.set(new Tagged(Messages.DHPart1,
                            new DHPartMessage(msg.type, msg.h1, msg.pkey, msg.mac)));
        // TODO(mling): Calculate SAS and verify with user.

      } else if (type == 'DHPart2') {
        // Verify that this is the sam ehk.
        var commit = this.messages_[Messages.Commit].value;
        if (commit.hk !== this.hashString(msg.pkey)) {
          console.log("hash(pkey)/hk mismatch for DHPart2 (",msg.pkey,") vs Commit (",
                      commit.hk, ")");
          this.resolve(false);
          return;
        }
        // Verify the mac of the Commit.
        if (commit.mac !== this.mac(msg.h1, commit.h2 + commit.hk +
                                    commit.clientVersion + commit.hvi)) {
          console.log("MAC mismatch for Commit found. h1: ", msg.h1,
                      " and Commit: ", commit);
          this.resolve(false);
          return;
        }

        this.set(new Tagged(Messages.DHPart2,
                            new DHPartMessage(msg.type, msg.h1, msg.pkey,
                                              msg.mac)));
        // TODO(mling): Calculate SAS and verify with user.

      } else if (type == 'Confirm1') {
        // Validate DHpart1
        var dhpart1 = this.messages_[Messages.DHPart1].value;
        if (dhpart1.mac !== mac(msg.h0, dhpart1.h1 + dhpart1.pkey)) {
          console.log("MAC mismatch for DHPart1 found. h0: ", msg.h0,
                      " and DHPart1: ", dhpart1);
          this.resolve(false);
          return;
        }
        this.set(new Tagged(Messages.Confirm1,
                            new CommitMessage(msg.type, msg.h0, msg.mac)));

      } else if (type == 'Comfirm2') {
        // Validate DHpart2
        var dhpart2 = this.messages_[Messages.DHPart2].value;
        if (dhpart2.mac !== mac(msg.h0, dhpart2.h1 + dhpart2.pkey)) {
          console.log("MAC mismatch for DHPart2 found. h0: ", msg.h0,
                      " and DHPart2: ", dhpart2);
          this.resolve(false);
          return;
        }
        this.set(new Tagged(Messages.Confirm2,
                            new CommitMessage(msg.type, msg.h0, msg.mac)));
        this.resolve(true);

      } else if (type == 'Conf2Ack') {
        this.set(new Tagged(Messages.Conf2Ack, new Conf2AckMessage(msg.type)));
        this.resolve(true);
      }
      this.sendNextMessage();
    } else {
      // reject the message for member key mismatch.
      console.log("Invalid message received: ", msg);
    }
  }

  private resolve(res:bool) {
    this.result_.resolve(res);
  }

  public start() :Promise<bool>{
    sendNextMessage();
    this.result_ = new Promise<bool>();
    return result_;
  }

  public sendNextMessage() {
    // Look at where we are in the conversation.
    // - figure out the latest message that isn't in the set.
    // - see if we have its prereq.
    // - send it.
    var msgType;
    if (this.role_ == 0) {
      if (this.messages_[Messages.Conf2Ack]) {
        return; // all done.
      } else if (this.messages_[Messages.Confirm1]) {
        msgType = Messages.Confirm2;
      } else if (this.messages_[Messages.DHPart1]) {
        msgType = Messages.DHPart2;
      } else if (this.messages_[Messages.Hello2]) {
        msgType = Messages.Commit;
      } else {
        msgType = Messages.Hello1;
      }
    } else {
      if (this.messages_[Messages.Conf2Ack]) {
        return; // all done.
      } else if (this.messages_[Messages.Confirm2]) {
        msgType = Messages.Conf2Ack;
      } else if (this.messages_[Messages.DHPart2]) {
        msgType = Messages.Confirm1;
      } else if (this.messages_[Messages.Commit]) {
        msgType = Messages.DHPart1;
      } else {
        msgType = Messages.Hello2;
      }
    }
    if (!this.message_[msgType]) {
      var msg = this.generate(msgType);
      this.set(msg);
      this.delegate_.sendMessage(msg);
    }
  }

  private structuralVerify(msg:any) :bool{
    // Verify that none of the values are blank.
    var allKeys = Object.keys(msg);
    for (var k in allKeys) {
      if (msg[k].length == '') {
        console.log("Verify msg ", msg, " got empty value for key ", k);
        return false;
      }
    }
    // Verify that we only have the keys we're expecting.
    if (allKeys.sort().join() !== this.keyMap_[msg.type]) {
      console.log("Verify msg ", msg, " bad key set.  Wanted ", this.keyMap_[msg.type], " got ",
                  allKeys.sort().join());
      return false;
    }
    // Verify that we have all the prerequisite messages for this one.
    for (var m in this.prereqMap_[msg.type]) {
      if (!this.messages_[m]) {
        console.log("Verify msg ", msg, " missing prerequisite ", m);
        return false;
      }
    }
    return true;
  }

  private generate(type: Messages.Type) :Messages.Tagged {

  }
  private set(message: Messages.Tagged) :bool {
  }
};
// A heavily validating history store for messages sent and received
// in a ZRTP conversation.  ConversationHistory validates received
// messages.  This includes MAC validation and hash validation.
export class ConversationHistory {
  // The entity that sends Hello1 is role number 0.  The one that
  // sends Hello2 (in response to Hello1) is role number 1.  Either
  // can send Commit.  The first one that does is called the
  // initiator.
  private var initRole_ :number;
  enum MessageType { Hello1, Hello2, Commit, DHPart1, DHPart2, Confirm1,
                     Confirm2, Conf2Ack };

  private messages_: { [Message]:any };

  constructor(messages: {[Message]:any}, initRole :number) {
    if (messages) {
      // Deep copy
      this.messages_ = JSON.parse(JSON.stringify(messages));
    } else {
      this.messages_ = {};
    }
    this.initRole_ = -1;
    if (initRole && initRole >= 0 && initRole < 2) {
      this.initRole_ = initRole;
    }
  }

  // One of the key complexities in this history will be who a given
  // client is: the first one to say hello or the second, and
  // separtely, whether they're the initiator.
  //
  // So, we assign role numbers based on who said hello first.  Then
  // we separately store which role number started the secure phase
  // with the Commit message.
  public hasInitRole () :bool {
    return this.initRole_ >= 0;
  }

  public isInitRole(role :number) :bool {
    return this.initRole_ == role;
  }

  private insertIfPresent(msg :Message, dest: {[Message]:any}) {
    if (this.messages_[msg]) {
      dest[msg] = this.messages_[msg];
    }
  }

  public messagesForRole(senderRole: number) : [Message] {
    var result:[Message] = [];
    if (senderRole == 0) {
      result.push(Hello1);
    } else {
      result.push(Hello2);
    }
    if (this.initRole_ >= 0) {
      if (senderRole == this.initRole_) {
        result.push(Commit);
        result.push(DHPart2);
        result.push(Confirm2);
      } else {
        result.push(DHPart1);
        result.push(Confirm1);
        result.push(Conf2Ack);
      }
    }
    return result;
  }

  // Returns the messages sent by the given role.
  public messagesSentByRole(role :number) : {[Message]:any} {
    var result = {};
    var messages = this.messagesForRole(role);
    for (var m in messages) {
      insertIfPresent(m, result);
    }
    return result;
  }

  public validMessageForRole(senderRole:number, msg :Message) :bool{
    return messagesForRole(senderRole).indexOf(msg) != -1;
  }

  // Adds to the message history.
  public saveMessage(senderRole:number, msg:Message, body:any) {
    if (msg == Commit && this.initRole_ == -1) {
      this.initRole_ = senderRole;
    }
    if (validMessageForRole(senderRole, msg)) {
      this.messages_[msg] = body;
    } else {
      throw new Error("Role " + senderRole + " cannot send " + msg);
    }
  }

  public getMessage(senderRole:number, msg:Message) :any {
    if (validMessageForRole(senderRole, msg)) {
      return this.messages_[msg];
    } else {
      throw new Error("Role " + senderRole + " could not have sent " + msg);
    }
  }
};

export class Participant {
  // Last sent message on our side.
  private state_ :ConversationHistory.Message;
  private peerRole_ :number;
  constructor(private role_: number,
              private history_ :ConversationHistory,
              private delegate_ :ZRTPDelegate) {
    if (this.role_ == 0) {
      this.peerRole_ = 1;
    } else {
      this.peerRole_ = 0;
    }
    // Figure out where we are in the conversation.
    if (!this.history_.hasInitRole()) {
      state_ = role_ == 0? ConversationHistory.Hello1 : ConversationHistory.Hello2;
    } else {
      var allMySentMessages = history_.messagesSentByRole(this.role_);
      var largestSentMessage = 0;
      for (var k in allMySentMessages) {
        if (k > largestSentMessage) {
          largestSentMessage = k;
        }
      }
      this.state_ = largestSentMessage;
    }
  }

  // TODO: wrap in a larger interface type that has a single field to
  // identify the message.
  public receiveMessage(msg:Message, value:any) {
    history_.saveMessage(this.peerRole_, msg, value);
    switch (msg) {

    }
  }
}