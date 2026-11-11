// A compact list of very common passwords (lower-case), used by CommonPasswordValidator.
// Django ships 20,000 entries; this keeps the Worker bundle small. Pass `passwords` to the validator
// for a bigger list.
const LIST = `
123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon 123123 baseball abc123 football
monkey letmein 696969 shadow master 666666 qwertyuiop 123321 mustang 1234567890 michael 654321 superman
1qaz2wsx 7777777 121212 000000 qazwsx 123qwe killer trustno1 jordan jennifer zxcvbnm asdfgh hunter buster
soccer harley batman andrew tigger sunshine iloveyou 2000 charlie robert thomas hockey ranger daniel starwars
klaster 112233 george computer michelle jessica pepper 1111 zxcvbn 555555 11111111 131313 freedom 777777
pass maggie 159753 aaaaaa ginger princess joshua cheese amanda summer love ashley nicole chelsea biteme
matthew access yankees 987654321 dallas austin thunder taylor matrix mobilemail mom monitor monitoring
montana moon moscow william corvette hello martin heather secret merlin diamond 1234qwer gfhjkm hammer
silver 222222 88888888 anthony justin test bailey q1w2e3r4t5 patrick internet scooter orange 11111 golfer
cookie richard samantha bigdog guitar jackson whatever mickey chicken sparky snoopy maverick phoenix camaro
peanut morgan welcome falcon cowboy ferrari samsung andrea smokey steelers joseph mercedes dakota arsenal
eagles melissa boomer booboo spider nascar monster tigers yellow xxxxxx 123123123 gateway marina diablo
bulldog qwer1234 compaq purple hardcore banana junior hannah 123654 porsche lakers iceman money cowboys
987654 london tennis 999999 ncc1701 coffee scooby 0000 miller boston q1w2e3r4 brandon yamaha chester
mother forever johnny edward 333333 oliver redsox player nikita knight fender barney midnight please brandy
chicago badboy slayer rangers charles angel flower bigdaddy rabbit wizard jasper enter rachel chris steven
winner adidas victoria natasha 1q2w3e4r jasmine winter prince panties marine ghbdtn fishing cocacola
casper james 232323 raiders 888888 marlboro gandalf asdfasdf crystal 87654321 12344321 golden 8675309
sexy 101010 qwe123 password1 password123 abcd1234 admin admin123 administrator root toor changeme default
guest login passw0rd p@ssw0rd p@ssword welcome1 welcome123 letmein123 qwerty123 qwerty1 1q2w3e 1q2w3e4r5t
zaq12wsx zaq1zaq1 asdf1234 asdfghjkl qazwsxedc 1qazxsw2 football1 baseball1 iloveyou1 princess1 sunshine1
monkey1 dragon1 shadow1 master1 superman1 michael1 jennifer1 jordan23 liverpool chelsea1 arsenal1 manchester
barcelona realmadrid soccer1 hockey1 tigger1 charlie1 summer1 winter1 spring autumn hello123 hello1
loveme lovely loveyou babygirl baby123 angel1 angels butterfly flower1 pokemon naruto starwars1 matrix1
trustno1 whatever1 nothing secret1 secret123 test123 test1 testing tester demo sample example user user123
pass123 pass1234 password12 password1234 passport passpass qwertyui zxcvbnm1 asdfgh1 qwert 12qwaszx 1qaz2wsx3edc
abc12345 abcdef abcdefg abcdefgh abc123456 a123456 aa123456 a1b2c3 a1b2c3d4 123abc 1a2b3c 0987654321
121212121 147258369 159357 147852 147258 258456 741852963 963852741 369258147 123456a 123456q 12345a
12345q 123456789a 1234567a 112233445566 11223344 1122334455 102030 10203040 1020304050 123654789 0123456789
666666666 7777777777 9999999 99999999 00000000 0000000 1111111 1111111111 12121212 123412341234 1212
asdasd asdasdasd qweqwe qweqweqwe zxczxc azerty azerty123 qwertz qwertz123 iloveu ilovegod jesus jesus1
christ blessed blessing faith hope trinity heaven church god lord savior amen bible praise hallelujah
mustang1 ferrari1 porsche1 bmw mercedes1 honda toyota nissan ford chevy camaro1 corvette1 harley1 ducati
pepper1 cheese1 coffee1 chocolate cookie1 cupcake pizza banana1 apple apple123 orange1 lemon cherry peaches
sweet sweetie sweetheart honey sugar candy kitty kitten puppy doggy tiger lion bear eagle wolf fox
shark dolphin unicorn rainbow sunshine12 starlight moonlight midnight1 shadow12 silver1 golden1 diamond1
crystal1 jessica1 ashley1 amanda1 michelle1 nicole1 samantha1 heather1 melissa1 hannah1 sarah emily
emma olivia sophia isabella madison daniel1 david robert1 thomas1 william1 joseph1 charles1 richard1
anthony1 matthew1 andrew1 joshua1 christopher justin1 brandon1 tyler ryan jacob nathan kevin jason eric
`

/** Common passwords (lower-case). */
export const COMMON_PASSWORDS: ReadonlySet<string> = new Set(LIST.split(/\s+/).filter(Boolean))
