/** 
* Password Entropy
* 
* This jQuery plug-in is built to give an estimate of the entropy of a password.
* Initial calculations assume a randomly generated password is used, and then
* applies a heuristics approach to penalize some common problems that arise
* with human-generated passwords.
* 
* Some of the patterns used for creating the estimates are based on data collected
* in the paper "Testing Metrics for Password Creation Policies by Attacking Large 
* Sets of Revealed Passwords" by Weir et. al. and can be recommended as further
* reading for those interested.
*
* The default blacklisted passwords are based on lists downloaded from
* http://www.skullsecurity.org/ and then compiled to match the purpose of this
* plug-in.
*
* MIT LICENSE
* Copyright (C) 2011 by Erik Brännström
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*/

(function( $ ){

    $.fn.passwordEntropy = function(options) {

        var log2 = function (value) {
            return Math.log(value)/Math.log(2)
        };

        var defaults = {
            'display'     : '.strength',
            'functions'    : [
                function(entropy, password) {
                    // Penalize passwords with:
                    //  - only letters followed by 1 to 3 digits
                    //  - beginning with single uppercase followed by lowercase
                    //  - only letters followed by a single special character
                    if( password.match(/^[a-zA-Z]+[0-9]{1,3}$/)
                    ||  password.match(/^[A-Z][a-z]+$/)
                    ||  password.match(/^[a-zA-Z]+[^a-zA-Z0-9]$/) )
                        return entropy - 8;
                    else
                        return entropy;
                },
                function(entropy, password) {
                    // Make sure password is not in blacklist 
                    if(settings.blacklist.length == 0 || jQuery.inArray(password.toLowerCase(), settings.blacklist) === -1)
                        return entropy;
                    
                    return log2(settings.blacklist.length);
                }
            ],
            'strings'   : ['Very weak', 'Weak', 'Pass', 'Strong', 'Very strong', 'Super strong'],
            'classes'   : ['very-weak', 'weak', 'pass', 'strong', 'very-strong', 'super-strong'],
            // Default blacklist contains 598 passwords that are at least 8 characters long.
            // Based on Twitter's disallowed passwords, John the Ripper dictionary and most common RockYou passwords.
            'blacklist' : ['password','computer','internet','baseball','michelle','changeme','trustno1','12345678','butthead','football','iloveyou','jennifer','jonathan','poohbear','sunshine','victoria','whatever','alexander','asdfjkl;','basketball','elephant','goodluck','lacrosse','ncc1701d','shithead','stephanie','a1b2c3d4','christin','franklin','kingfish','maryjane','maverick','mitchell','mountain','pearljam','princess','startrek','steelers','sunflower','superman','babylon5','benjamin','bluebird','chocolate','cocacola','einstein','explorer','flamingo','katherine','porsche911','security','snowball','thunderbird','training','alexandr','beautiful','caroline','challenge','charlotte','coltrane','crawford','elizabeth','firebird','fletcher','fountain','gabriell','garfield','godzilla','grateful','greenday','icecream','informix','jeanette','kathleen','lionking','majordomo','margaret','mariposa','marlboro','mercedes','metallic','monopoly','ncc1701e','nicholas','penelope','phoenix1','remember','republic','research','samantha','scarlett','snickers','snoopdog','spitfire','starwars','stingray','sumuinen','valentine','veronica','warriors','zeppelin','!@#$%^&*','broadway','raistlin','abcd1234','acropolis','asdfasdf','asdfghjk','babydoll','beatrice','blowfish','bluefish','bullshit','business','california','cannondale','carebear','catalina','catherine','champion','chelsea1','chester1','christian','colorado','columbia','commander','cordelia','creative','danielle','database','deadhead','dickhead','dragonfly','electric','excalibur','feedback','francesco','francine','francois','fuckface','gargoyle','goldfish','gretchen','harrison','idontknow','intrepid','jethrotull','johanna1','jordan23','kangaroo','kimberly','lawrence','liverpool','marathon','michael1','midnight','montreal','mortimer','nirvana1','notebook','overkill','patricia','pinkfloyd','predator','prometheus','rastafarian','reynolds','ricardo1','roadrunner','robinhood','robotech','rocknroll','salasana','sapphire','scarecrow','skywalker','smashing','snowflake','strawberry','sundance','superfly','swimming','teddybear','temporal','terminal','thejudge','thursday','valhalla','warcraft','williams','windsurf','woofwoof','wrangler','xcountry','11111111','88888888','bismillah','cardinal','front242','geronimo','madeline','sidekick','sterling','waterloo','wolverine','aardvark','aerobics','airborne','allstate','altamira','anderson','andromed','anything','applepie','aquarius','asdf1234','asdf;lkj','assmunch','barnyard','bernardo','birthday','blackjack','blueeyes','bluejean','brewster','butterfly','calendar','campbell','catwoman','chainsaw','chameleon','chinacat','chouette','chris123','christmas','christopher','clarkson','clueless','concorde','confused','coolbean','cornflake','corvette','crescent','crusader','cunningham','daedalus','damogran','darkstar','datatrain','december','deeznuts','dillweed','director','dominique','dontknow','downtown','dutchess','enterprise','fairview','ferguson','fireball','fishhead','flanders','florida1','flowerpot','frederic','freebird','froggies','frontier','gammaphi','garfunkel','gateway2','germany1','gilgamesh','halloween','hallowell','hamilton','happy123','happyday','hardcore','hawkeye1','heather1','heather2','hedgehog','hello123','hellohello','heythere','highland','histoire','hongkong','hosehead','hydrogen','indonesia','instruct','integral','isabelle','jamesbond','jeepster','jeffrey1','justdoit','justice4','kalamazo','katerina','kittycat','kristine','laserjet','lissabon','loislane','lonestar','longhorn','makeitso','manageme','marielle','marshall','mattingly','meatloaf','mechanic','michigan','microsoft','millenium','mobydick','montana3','montrose','moonbeam','morecats','morpheus','motorola','munchkin','mustang1','napoleon','national','neutrino','newaccount','newyork1','nicklaus','nightshadow','nightwind','nintendo','obsession','paradigm','patriots','performa','peterpan','phialpha','phillips','pianoman','pipeline','precious','printing','provider','qwerty12','qwertyui','rachelle','redcloud','redskins','renegade','revolution','rhjrjlbk','richard1','richards','richmond','robotics','rootbeer','rossigno','ruthless','saturday','schnapps','scoobydoo','scooter1','scorpion','september','services','shanghai','sigmachi','signature','skipper1','sprocket','starbuck','stargate','starlight','stranger','student2','superstar','sweetpea','swordfish','tacobell','tazdevil','testtest','thankyou','thelorax','thisisit','thompson','thrasher','tightend','tinkerbell','transfer','transport','treasure','trombone','ultimate','vacation','vincent1','virginia','webmaster','whocares','whoville','william1','winniethepooh','wolfgang','xxxxxxxx','yogibear','00000000','1234qwer','21122112','99999999','anaconda','apollo13','blizzard','carolina','chandler','changeit','charlie1','chiquita','chocolat','christia','christoph','classroom','courtney','dolphins','fearless','good-luck','graymail','guinness','homebrew','lorraine','macintosh','nebraska','newcourt','politics','portland','property','softball','stephani','valentin','zhongguo','access14','bigdaddy','mistress','password1','password12','password123','redwings','rush2112','srinivas','123456789','babygirl','1234567890','987654321','spongebob','princesa','alexandra','estrella','princess1','alejandro','brittany','alejandra','tequiero','blink182','fernando','cristina','babygurl','november','mahalkita','gabriela','iloveyou2','pictures','hellokitty','babygirl1','angelica','iloveyou1','inuyasha','sebastian','spiderman','0123456789','barcelona','slipknot','cutiepie','789456123','portugal','volleyball','rockstar','cristian','chrisbrown','lollipop','qwertyuiop','harrypotter','ihateyou','christine','johncena','lovelove','metallica','myspace1','babyblue','fernanda','westlife','slideshow','asdfghjkl','santiago','sweetheart','12345678910','leonardo','sexygirl','anthony1','skittles','brooklyn','colombia','christina','teiubesc','147258369','francisco','amorcito','angelito','manchester','linkinpark','fuckyou1','bestfriend','sporting','truelove','savannah','scotland','ilovehim','estrellita','brandon1','loverboy','emmanuel','999999999','westside','mauricio','preciosa','shopping','isabella','martinez','friendster','valentina','fuckyou2','sunshine1','gangster','darkangel','bettyboop','jessica1','cheyenne','bestfriends','daddysgirl','billabong','buttercup','zacefron','tokiohotel','bubblegum','darkness','lollypop','sexybitch','hotstuff','babylove','angelina','playgirl','football1','milagros','margarita','undertaker','capricorn','cheerleader','password2','matthew1','carlitos','michelle1','cinderella','jesuschrist','ilovejesus','tazmania','princesita','jesucristo','lipgloss','741852963','hernandez','pussycat','gorgeous','simpsons','panthers','hollywood','ilovegod','kristina','sexymama','scarface','0987654321','jeremiah','pineapple','butterfly1']
        };

        // Recursively merge user options with default settings and fix array merge
        var settings = $.extend({}, defaults, options);
        if(options) {
            settings.functions = defaults.functions.concat(options.functions);
            settings.blacklist = defaults.blacklist.concat(options.blacklist);
        }

        return this.each(function() {

            $(this).bind('keyup', function() {
                var psw = $(this).val();

                // Decide the number of characters in the character set
                var set = 0;
                if(psw.match(/[a-z]/))
                    set += 26;
                if(psw.match(/[A-Z]/))
                    set += 26;
                if(psw.match(/[0-9]/))
                    set += 10;
                if(psw.match(/[\._!\- @*#\/&]/)) // Most common special characters based on RockYou passwords
                    set += 10;
                if(psw.match(/[^a-zA-Z0-9\._!\- @*#\/&]/))
                    set += 22;

                // Calculate entropy in base 2
                var combinations = Math.pow(set, psw.length);
                var entropy = log2(combinations);

                // Run functions to modify password entropy
                for (var i in settings.functions) {
                    entropy = settings.functions[i](entropy, psw);
                }
                
                // Set message display
                var res = 0;
                if(entropy >= 78)
                    res = 5;
                else if(entropy >= 66)
                    res = 4;
                else if(entropy >= 56)
                    res = 3;
                else if(entropy >= 48)
                    res = 2;
                else if(entropy >= 40)
                    res = 1;
                
                // Display results
                $(settings.display).removeClass(settings.classes.join(' '))
                        .addClass(settings.classes[res])
                        .html(settings.strings[res]);
            });

        });
    };
})( jQuery );