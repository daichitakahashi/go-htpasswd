package htpasswd

import (
	"fmt"
	"testing"
)

type md5Datum struct {
	password string
	salt     string
	hashed   string
	prefix   string
}

var md5CryptTestData = []md5Datum{
	md5Datum{"mickey5", "D89ubl/e", "dJ8XW4DfrJHTrnwCdx3Ji1", PrefixCryptMd5},
	md5Datum{"alexandrew", "D89ubl/e", "xuQ74IxhM3J10sv0QHVgA/", PrefixCryptMd5},
	md5Datum{"hawaiicats78", "D89ubl/e", "Y07COBJSUbNDlYlFyRYUp.", PrefixCryptMd5},
	md5Datum{"DIENOW", "D89ubl/e", "4IZ.tBiqvtxt7Dpt1MkgE1", PrefixCryptMd5},
	md5Datum{"e8f685", "D89ubl/e", "mLrBtDw8UTdAX7jDZLQIB0", PrefixCryptMd5},
	md5Datum{"Rickygirl03", "D89ubl/e", "gDHt/53o.SrKMB2Ts06ll1", PrefixCryptMd5},
	md5Datum{"123vb123", "D89ubl/e", "rRYNMP4siiirAmmukKbLH1", PrefixCryptMd5},
	md5Datum{"sheng060576", "D89ubl/e", "eZSBBncGvTB0M0FC5y25f/", PrefixCryptMd5},
	md5Datum{"hansisme", "D89ubl/e", "ulbSP3eTh0fe.Xi.1yZUK0", PrefixCryptMd5},
	md5Datum{"h4ck3rs311t3", "D89ubl/e", ".eWY6zxlyQZR2H/Wl1oBv.", PrefixCryptMd5},
	md5Datum{"K90JyTGA", "D89ubl/e", "z92umtR06bhr7asKE0qys/", PrefixCryptMd5},
	md5Datum{"aspire5101", "D89ubl/e", "TAcr1BfieDgQrINZM5ob4/", PrefixCryptMd5},
	md5Datum{"553568", "D89ubl/e", "/hZIUw5diSqk2M17H8ya2/", PrefixCryptMd5},
	md5Datum{"SRI", "D89ubl/e", "sQaL5tfFD85YivTet25eA0", PrefixCryptMd5},
	md5Datum{"maxmus", "D89ubl/e", "d/DZx6g1NFNtzU4.7a8zz1", PrefixCryptMd5},
	md5Datum{"a5xp9707", "D89ubl/e", "Ss.xxvcZk.hyZhfw.uHu./", PrefixCryptMd5},
	md5Datum{"tomasrim", "D89ubl/e", "0P5vwLE5BrTDStMNUSVvy.", PrefixCryptMd5},
	md5Datum{"2a0mag", "D89ubl/e", "6.cSxEJwebnwRhE3Hzn0p0", PrefixCryptMd5},
	md5Datum{"wmsfht", "D89ubl/e", "C/xkXc8Y1I58TITNT5B000", PrefixCryptMd5},
	md5Datum{"webmaster2364288", "D89ubl/e", "C793xtKVyHtLgE9kv9F3G/", PrefixCryptMd5},
	md5Datum{"121516m", "D89ubl/e", "l77x/.bF/SKs9j1fzZsxT0", PrefixCryptMd5},
	md5Datum{"T69228803", "D89ubl/e", "Kyx0nL8mqLVQSTEoLozXf0", PrefixCryptMd5},
	md5Datum{"qq820221", "D89ubl/e", "/K9HdFFaZs6fQtHeg50i2/", PrefixCryptMd5},
	md5Datum{"chenfy", "D89ubl/e", "5KXGSkIs4eVf9.vv784h2/", PrefixCryptMd5},
	md5Datum{"www.debure.net", "D89ubl/e", "Unn6gxvier6BbNqXXggcC1", PrefixCryptMd5},
	md5Datum{"1333e763", "D89ubl/e", "y6uoa9UFNh89NqUYl52rU1", PrefixCryptMd5},
	md5Datum{"burberries", "D89ubl/e", "/hj9e6a9Ka4A6PLtscUAJ/", PrefixCryptMd5},
	md5Datum{"chanmee14", "D89ubl/e", "FaTM181xgGpilXHhzKspp/", PrefixCryptMd5},
	md5Datum{"65432106543210", "D89ubl/e", "juw3fg2cPTz96Styto/mD/", PrefixCryptMd5},
	md5Datum{"powernet", "D89ubl/e", "VPgIKROD.HnIac7efgPqp/", PrefixCryptMd5},
	md5Datum{"a2d8i6a7", "D89ubl/e", "YHiBHNKujH.hOoduR6yI30", PrefixCryptMd5},
	md5Datum{"gvs9ptc", "D89ubl/e", "EZatY2FiaT38R7pJM28Ta1", PrefixCryptMd5},
	md5Datum{"Pookie", "D89ubl/e", "nXBo5NIufmx/azSj5c7xn0", PrefixCryptMd5},
	md5Datum{"lorissss", "D89ubl/e", "4c4jEBluS1Z/5gwpP5IHP1", PrefixCryptMd5},
	md5Datum{"ess", "D89ubl/e", "OTaO6MXXx/9Kzgdax4IFT1", PrefixCryptMd5},
	md5Datum{"sparra", "D89ubl/e", "fyLMarn1NGkBlrVvnOkWe/", PrefixCryptMd5},
	md5Datum{"allysson", "D89ubl/e", "BSEg4wMYeZZrqQRbgLZQ40", PrefixCryptMd5},
	md5Datum{"99128008", "D89ubl/e", "09Q0RgEq0luH52Q5D1r5h0", PrefixCryptMd5},
	md5Datum{"evisanne", "D89ubl/e", "0CFkGtb.nFnwY0AsvIZ/p1", PrefixCryptMd5},
	md5Datum{"qfxg7x9l", "D89ubl/e", "mxD6Tg8iiXGn2iuap9dkZ1", PrefixCryptMd5},
	md5Datum{"03415", "D89ubl/e", "jTHXwK8wWOmCWMhV/Nqq6.", PrefixCryptMd5},
	md5Datum{"87832309", "D89ubl/e", "eQQM1N3kzqYaJsIHAuma3.", PrefixCryptMd5},
	md5Datum{"816283", "D89ubl/e", "VPIMSuAdaNExEPg1o6BR21", PrefixCryptMd5},
	md5Datum{"banach12", "D89ubl/e", "tMKU2NslMUsgBVMJ4Z8Bw1", PrefixCryptMd5},
	md5Datum{"sjdszpsc", "D89ubl/e", "Zo9sQwDO9imDRzQjAvSit.", PrefixCryptMd5},
	md5Datum{"changsing", "D89ubl/e", "BnGW9hkQkwO/Fpj6lLGKK/", PrefixCryptMd5},
	md5Datum{"56339388", "D89ubl/e", "Gc5RbOS3wD6GwQ8rbSJDB.", PrefixCryptMd5},
	md5Datum{"52114157", "D89ubl/e", "5lIEMaiA6epkGKq3ZJJr./", PrefixCryptMd5},
	md5Datum{"jinebimb", "D89ubl/e", "tFt1GFVE6wxs5UhiRIPJo0", PrefixCryptMd5},
	md5Datum{"erol43", "D89ubl/e", "WNTQoeaBUI6P1ypLfFBGz1", PrefixCryptMd5},
	md5Datum{"2yagos", "D89ubl/e", "U/zmE2HZ9arX1CFysF48F0", PrefixCryptMd5},
	md5Datum{"habparty!", "D89ubl/e", "p.bG9zn.rvJB7E2nGhleK0", PrefixCryptMd5},
	md5Datum{"tangjianhui", "D89ubl/e", "zal5AqxTqbMoo36DXwEQi0", PrefixCryptMd5},
	md5Datum{"serandah", "D89ubl/e", "s8mCg6jFym06sqZWoOXZr/", PrefixCryptMd5},
	md5Datum{"mirrages", "D89ubl/e", "80YBEXI4zCLlO9bOld9ey/", PrefixCryptMd5},
	md5Datum{"mantgaxxl", "D89ubl/e", "coCMG.asGxvMHowtOtD/p.", PrefixCryptMd5},
	md5Datum{"45738901", "D89ubl/e", "ZSf.3PkORJgZTiW3WmC0S0", PrefixCryptMd5},
	md5Datum{"g523minna", "D89ubl/e", "Q8Ti7BlgMjNwXCjzsvGz0.", PrefixCryptMd5},
	md5Datum{"j202020", "D89ubl/e", "GplTzL8mgIki4Grxkmsnn0", PrefixCryptMd5},
	md5Datum{"g@mmaecho", "D89ubl/e", "SMrOpSVsLdDZh0fgSv3RQ.", PrefixCryptMd5},
	md5Datum{"042380", "D89ubl/e", "L7c4tHvipozBibsgDlIae.", PrefixCryptMd5},
	md5Datum{"ASRuin", "D89ubl/e", "0kSaA27U/3XSYr8ysXYk00", PrefixCryptMd5},
	md5Datum{"061990", "D89ubl/e", "h0QjZLtAyLFIS0RHzUC0g0", PrefixCryptMd5},
	md5Datum{"ysoline", "D89ubl/e", "m/HGZlMaYri6dyglbebGq1", PrefixCryptMd5},
	md5Datum{"liuzhouzhou", "D89ubl/e", "ZCeDrrlRD4z0GuWUhkRIp/", PrefixCryptMd5},
	md5Datum{"b0000000wind", "D89ubl/e", "mrunNmbLqlK6GBjHAyXme0", PrefixCryptMd5},
	md5Datum{"7913456852", "D89ubl/e", "LAleKOBmjHO.JkMqxZJva0", PrefixCryptMd5},
	md5Datum{"9008", "D89ubl/e", "PsZG8hCSDwlu61oK/xVwY/", PrefixCryptMd5},
	md5Datum{"waitlin11", "D89ubl/e", "FI4Kdq4kuDrE.02FKhu7l.", PrefixCryptMd5},
	md5Datum{"8fdakar", "D89ubl/e", "vM6r7Y64Zfo7Tw0YkPT.T.", PrefixCryptMd5},
	md5Datum{"eisball", "D89ubl/e", "AiLLO.VR/Z6HBLIsg59yg/", PrefixCryptMd5},
	md5Datum{"jenna17", "D89ubl/e", "NZ7SaJ8LroRQacSqrP7fp0", PrefixCryptMd5},
	md5Datum{"belkadonam", "D89ubl/e", "gfKqHDjTyhd5guuVyAg/i/", PrefixCryptMd5},
	md5Datum{"tfyuj9JW", "D89ubl/e", "Z45Dy1hE/XhDlnLJh63w80", PrefixCryptMd5},
	md5Datum{"nihaijidema", "D89ubl/e", "MmNfgZpCBgohV/RiCqEeh0", PrefixCryptMd5},
	md5Datum{"talapia", "D89ubl/e", "yx7VuwWX2kJ3fgelcamZp/", PrefixCryptMd5},
	md5Datum{"7376220", "D89ubl/e", "qSMTwpxirNVKQmnv0LKGt/", PrefixCryptMd5},
	md5Datum{"c7m8e1xsc3", "D89ubl/e", "i1mU8nOLP85sWe.XN35Cw/", PrefixCryptMd5},
	md5Datum{"84129793", "D89ubl/e", "/MSgRW0uYjW5NdqyBJdPB.", PrefixCryptMd5},
	md5Datum{"test1000", "D89ubl/e", "4pXO/YHKqJ51rx2dWolr.1", PrefixCryptMd5},
	md5Datum{"ecmanhatten", "D89ubl/e", "xLJthQG.pQzgK8oVOGzNB1", PrefixCryptMd5},
	md5Datum{"EvanYo3327", "D89ubl/e", "l1Q0BEAEDlXPW44kj5xhR0", PrefixCryptMd5},
	md5Datum{"269john139", "D89ubl/e", "qnjT/g8iIRqgJjEdutYMI/", PrefixCryptMd5},
	md5Datum{"3348159zw", "D89ubl/e", "5zxhC1KC7L1bfJPiZRzXp1", PrefixCryptMd5},
	md5Datum{"lu184020", "D89ubl/e", "IaTFU11RpmJaS9o4H6Zbd0", PrefixCryptMd5},
	md5Datum{"aszasw", "D89ubl/e", "pi5D8IwHVYgPyiXuIuW/Z.", PrefixCryptMd5},
	md5Datum{"33059049", "D89ubl/e", "mQukEUOQ3Y67xULFLxenN1", PrefixCryptMd5},
	md5Datum{"li3255265", "D89ubl/e", "pwTwGBzTj/f4qRvrXWDeH1", PrefixCryptMd5},
	md5Datum{"kerrihayes", "D89ubl/e", "eSRqyebfyJIf.wGwNWJiF/", PrefixCryptMd5},
	md5Datum{"0167681809", "D89ubl/e", "aaKVVJe1BPZbXaKqWDhJH.", PrefixCryptMd5},
	md5Datum{"stefano123", "D89ubl/e", "myjNwn1J/Xur2sGPb2KDW/", PrefixCryptMd5},
	md5Datum{"15054652730", "D89ubl/e", "Sk9rTdAjux9EEWjIi983s.", PrefixCryptMd5},
	md5Datum{"natdvd213", "D89ubl/e", "49aMem462jQkqqZ1YCYtu1", PrefixCryptMd5},
	md5Datum{"680929", "D89ubl/e", "SRje2pCzH8NjNInSkec5p/", PrefixCryptMd5},
	md5Datum{"steelpad8", "D89ubl/e", "WYHvQD3.AucnP.fo2kgLP/", PrefixCryptMd5},
	md5Datum{"374710", "D89ubl/e", "MMK0xP5K1qHKsFsERRYCR.", PrefixCryptMd5},
	md5Datum{"394114", "D89ubl/e", "sVVqstvqjaibnGEvVOYci1", PrefixCryptMd5},
	md5Datum{"24347", "D89ubl/e", "VFIhSi8R9JmFPoZA4qDHI1", PrefixCryptMd5},
	md5Datum{"krait93", "D89ubl/e", "BlA2Z9tvvxDmV2dhtW14I0", PrefixCryptMd5},
	md5Datum{"5164794", "D89ubl/e", "52FunD0ymhST8S2IxFDwB.", PrefixCryptMd5},
	md5Datum{"rswCyJE5", "D89ubl/e", "3GLf6CNVmDH48iwOIVdYI/", PrefixCryptMd5},
	md5Datum{"31480019", "D89ubl/e", "d2eAdEkBFPJ/CBOM.MHET0", PrefixCryptMd5},
	md5Datum{"19830907ok", "D89ubl/e", "TbhdN5Ec9YD8bplz1A/ce/", PrefixCryptMd5},
	md5Datum{"zlsmhzlsmh", "D89ubl/e", "ZCOXuzvrKNSVFOIlo8NWa0", PrefixCryptMd5},
	md5Datum{"Zengatsu", "D89ubl/e", "5XqFN00zJn8eZ6mxIlNDn.", PrefixCryptMd5},
	md5Datum{"0127603331", "D89ubl/e", "Scb3wMWrVNXDw0FtBU2Bx.", PrefixCryptMd5},
	md5Datum{"axelle77", "D89ubl/e", "NKpZ4pHNMRByBtpN43qaR/", PrefixCryptMd5},
	md5Datum{"password2147", "D89ubl/e", "z3O5D9UC4h8DqIND7HI8e0", PrefixCryptMd5},
	md5Datum{"olixkl8b", "D89ubl/e", "ex2DzBcd0OK0xjWCk9gXn/", PrefixCryptMd5},
	md5Datum{"maiwen", "D89ubl/e", "nU.oBq2dK8u1/WYTb.qN./", PrefixCryptMd5},
	md5Datum{"198613", "D89ubl/e", "0DiN4Qgg78qXCKmCgn1v.0", PrefixCryptMd5},
	md5Datum{"s17kr8wu", "D89ubl/e", "0M452BZ4RsUFJlWmAzC/r0", PrefixCryptMd5},
	md5Datum{"biker02", "D89ubl/e", "kon/OQAJaw1jWzUVGF696/", PrefixCryptMd5},
	md5Datum{"m1399", "D89ubl/e", "rffe2sXyO8D4i8b/Zz4fN.", PrefixCryptMd5},
	md5Datum{"a2dc6a", "D89ubl/e", "hZxrfcVVudoH/vlLjHbO/0", PrefixCryptMd5},
	md5Datum{"zhd8902960", "D89ubl/e", "RXh0ZI2skEE34Okz7ZFkS.", PrefixCryptMd5},
	md5Datum{"parasuta", "D89ubl/e", "VdO1d5wKNz.082DfQBKdw/", PrefixCryptMd5},
	md5Datum{"the1secret", "D89ubl/e", "0O7aLsmdpnkds69gC8F3D0", PrefixCryptMd5},
	md5Datum{"teddy14", "D89ubl/e", "HWdm5snaFBk8FiDKaaIEQ1", PrefixCryptMd5},
	md5Datum{"4516388amt", "D89ubl/e", "xqw/ieFswTtoXsUl.qFiE/", PrefixCryptMd5},
	md5Datum{"245520", "D89ubl/e", "SzKFu0pIWn3aYOU4n8vD80", PrefixCryptMd5},
	md5Datum{"D34dw00d", "D89ubl/e", "lEOrH/zkoSs9gEPhWFzPY0", PrefixCryptMd5},
	md5Datum{"officiel", "D89ubl/e", "12DkA0BGmzbnFiXKQXOoO/", PrefixCryptMd5},
	md5Datum{"36653665", "D89ubl/e", "B4vLgohydtKjuwc3PDmLJ.", PrefixCryptMd5},
	md5Datum{"hipol", "D89ubl/e", "jANv18j9YRx4dSRG3e9dR0", PrefixCryptMd5},
	md5Datum{"Nylon0", "D89ubl/e", "5V/VlZE2LSVL/FXTfXSEY/", PrefixCryptMd5},
	md5Datum{"caitlyne6", "D89ubl/e", "iFyY3.Bcpd2jcEQLV5wSf.", PrefixCryptMd5},
	md5Datum{"dogzilla", "D89ubl/e", "DHPXon3QnoN6NBaTv2Mg5/", PrefixCryptMd5},
	md5Datum{"lemegaboss", "D89ubl/e", "DsPKwJLYCgtQGgiV1vsJW1", PrefixCryptMd5},
	md5Datum{"c0valerius", "D89ubl/e", "6DGzvs.WKNeB.s4iVzHL..", PrefixCryptMd5},
	md5Datum{"liseczek44", "D89ubl/e", "FwjNgb634KqRDONd9mWn10", PrefixCryptMd5},
	md5Datum{"saulosi", "D89ubl/e", "njQdR835SwHOdC9yOv7t3/", PrefixCryptMd5},
	md5Datum{"53522", "D89ubl/e", "0wHxUj/ReVsKDnUnPR/Su1", PrefixCryptMd5},
	md5Datum{"ajgebam", "D89ubl/e", "WAD9PbSIhz206tHvVsLIX0", PrefixCryptMd5},
	md5Datum{"freshplayer", "D89ubl/e", "LDUiW43DNTTs3M.00nnTs1", PrefixCryptMd5},
	md5Datum{"logistica1", "D89ubl/e", "PHYo0bAH5mMVAyjIC8piI0", PrefixCryptMd5},
	md5Datum{"12calo66", "D89ubl/e", "UyR/Od.i9HQ.st4.tpEI.0", PrefixCryptMd5},
	md5Datum{"kenno", "D89ubl/e", "5UD3WvZ/FwruX9YFVaIUT/", PrefixCryptMd5},
	md5Datum{"34639399", "D89ubl/e", "48eSiBnmw5e9w5giOn3ye1", PrefixCryptMd5},
	md5Datum{"0408636405", "D89ubl/e", "4X3PcQgOz0JVEvHTuFRh9.", PrefixCryptMd5},
	md5Datum{"weezer12", "D89ubl/e", "I1uauxPkvEIyk8UVXsDAQ.", PrefixCryptMd5},
	md5Datum{"9888735777", "D89ubl/e", "Ya0d5paah4ZnA8MbLTvqo/", PrefixCryptMd5},
	md5Datum{"7771877", "D89ubl/e", "1kY4BuTtTHHAEqBpDnh2B.", PrefixCryptMd5},
	md5Datum{"6620852", "D89ubl/e", "cfbSrTlsCwlAD3l7NWcjg.", PrefixCryptMd5},
	md5Datum{"98billiards", "D89ubl/e", "gKcTYvUdSIfR9/wxxVKh00", PrefixCryptMd5},
	md5Datum{"angelik", "D89ubl/e", "dr3IRAptFJZJihDhfJM6L1", PrefixCryptMd5},
	md5Datum{"86815057", "D89ubl/e", "W7HymXzTiMw19qnRxMFQz.", PrefixCryptMd5},
	md5Datum{"p16alfalfa", "D89ubl/e", "IDzuywgAHby2yNESi/cEu/", PrefixCryptMd5},
	md5Datum{"7236118", "D89ubl/e", "Fj8gIA/n0wzQQeFow.C7X1", PrefixCryptMd5},
	md5Datum{"glock17l", "D89ubl/e", "bbWZK6Y64mVxUFx/KiX1B1", PrefixCryptMd5},
	md5Datum{"sigmundm", "D89ubl/e", "p/oVop6W/YiSDKNOOKi6D1", PrefixCryptMd5},
	md5Datum{"ltbgeqsd", "D89ubl/e", "Qo8SMcE2S9QFp/zsRZeNG0", PrefixCryptMd5},
	md5Datum{"wqnd8k2m", "D89ubl/e", "q8ae/TEYgiU80vniBKIqo.", PrefixCryptMd5},
	md5Datum{"yangjunjie", "D89ubl/e", "gYAm1Win2xeG8VSEwezd30", PrefixCryptMd5},
	md5Datum{"manjinder", "D89ubl/e", "SFZgFYUGzipDnBs9gWwbr/", PrefixCryptMd5},
	md5Datum{"nick2000", "D89ubl/e", "J0Amxd2tBuLkMwRfT.9.l.", PrefixCryptMd5},
	md5Datum{"193416", "D89ubl/e", "s13zGQ31soCmTTRI6dtuO0", PrefixCryptMd5},
	md5Datum{"pang168", "D89ubl/e", "sROc1K.SSkTKzz17qcjkR.", PrefixCryptMd5},
	md5Datum{"454016", "D89ubl/e", "RyRsl5a2AMQomSbXxJwKd.", PrefixCryptMd5},
	md5Datum{"phair08", "D89ubl/e", "UPDj0.FApBTp/Mf8Pa5tG.", PrefixCryptMd5},
	md5Datum{"10252007cw", "D89ubl/e", "yDOxOyZ8Na.utOWkk19s01", PrefixCryptMd5},
	md5Datum{"zhuzhuzhu", "D89ubl/e", "2upo6jW4F5OLgMvJv3PuU1", PrefixCryptMd5},
	md5Datum{"metafunds", "D89ubl/e", "JpaGvclLj2SHhVAFBOqtT0", PrefixCryptMd5},
	md5Datum{"smash", "D89ubl/e", "XeFap1wOn3vppPM5HYTVp0", PrefixCryptMd5},
	md5Datum{"76387638", "D89ubl/e", "hRcYGGfn3HcDZcxeZtL.P1", PrefixCryptMd5},
	md5Datum{"S226811954", "D89ubl/e", "4t.pGGDRnT.epiS4XemUZ0", PrefixCryptMd5},
	md5Datum{"mintymoo00", "D89ubl/e", "MYyxqzymgUVhXkjLDPoeq1", PrefixCryptMd5},
	md5Datum{"seven711", "D89ubl/e", "Oes0cPGc7hQF.2nQgHThF0", PrefixCryptMd5},
	md5Datum{"924414", "D89ubl/e", "laB87gR5mmN/aNaQW37.E1", PrefixCryptMd5},
	md5Datum{"changchengxu", "D89ubl/e", "wvY4dNj.Q3U7pnEQgf/je1", PrefixCryptMd5},
	md5Datum{"alaska58", "D89ubl/e", "jRk3i8CF1C7Sh43qytD.31", PrefixCryptMd5},
	md5Datum{"7678208", "D89ubl/e", "0JCRZtaPgouKCrcAiF3290", PrefixCryptMd5},
	md5Datum{"szazsoo73", "D89ubl/e", "iZjmNH7GBYKN19Yl5IWF9.", PrefixCryptMd5},
	md5Datum{"3830371", "D89ubl/e", "QwDfjzDOqFgbsP52awbrP.", PrefixCryptMd5},
	md5Datum{"0qdzx66b", "D89ubl/e", "gwfYHJCUhkaGXuCTv9WYO1", PrefixCryptMd5},
	md5Datum{"09124248099", "D89ubl/e", "w98gHUCztuXegDue.AOTV.", PrefixCryptMd5},
	md5Datum{"bachrain", "D89ubl/e", "ROjdv8BY.9e3naiqMgt94/", PrefixCryptMd5},
	md5Datum{"sJsSdFBY", "D89ubl/e", "u0zmiD8YSiNfBZMgjhUkw/", PrefixCryptMd5},
	md5Datum{"676215000", "D89ubl/e", "FvH6jFxbT3BNYSJLNEkRE.", PrefixCryptMd5},
	md5Datum{"nimamapwoaini", "D89ubl/e", "50h2tbqHW9vagG7wL9YP71", PrefixCryptMd5},
	md5Datum{"nitsuj", "D89ubl/e", "BUr/iUuPZAJMn3LC7qzkq/", PrefixCryptMd5},
	md5Datum{"cukierek2003", "D89ubl/e", "70s6Is6uEwtFldtmotDhG.", PrefixCryptMd5},
	md5Datum{"seeder", "D89ubl/e", "k7PCEkvp2Pdm3HWWOBgmE0", PrefixCryptMd5},
	md5Datum{"00167148786", "D89ubl/e", "Cknm.cI/57fbdNnztPqVv/", PrefixCryptMd5},
	md5Datum{"ashok198", "D89ubl/e", "z1CwDc9dhBLK/3nPyrjN4/", PrefixCryptMd5},
	md5Datum{"kt2116", "D89ubl/e", "vA4kvwltG58Twovn9ia./1", PrefixCryptMd5},
	md5Datum{"another82", "D89ubl/e", "E75YhMUix/GZ6sGKMzKcH.", PrefixCryptMd5},
	md5Datum{"75995794", "D89ubl/e", "7Vjp3/aQgDkvrvihk.v020", PrefixCryptMd5},
	md5Datum{"19901130", "D89ubl/e", "ZrqfkcX5deYA89WLAiDsW.", PrefixCryptMd5},
	md5Datum{"gijs010389", "D89ubl/e", "s7khoFO35J03/IWR0Au9a/", PrefixCryptMd5},
	md5Datum{"26263199", "D89ubl/e", "oWHcMVYWZe.30EjvdVhSz/", PrefixCryptMd5},
	md5Datum{"hi1j42x8", "D89ubl/e", "TqtgsDnP6LyrpDriHI3g1.", PrefixCryptMd5},
	md5Datum{"6922235", "D89ubl/e", "BBVL9.H9p0kabiBuuGCP5.", PrefixCryptMd5},
	md5Datum{"67749330", "D89ubl/e", "nGYG2N2nmEZA7Xv0gpsUa.", PrefixCryptMd5},
	md5Datum{"ccpatrik", "D89ubl/e", "g.ihTAfr9HICtitiMed6U/", PrefixCryptMd5},
	md5Datum{"summer3011", "D89ubl/e", "BJ7gzGwNQmCy8WLTAzEcG0", PrefixCryptMd5},
	md5Datum{"331516", "D89ubl/e", "oroQkvFnt80PX9.DFORsH0", PrefixCryptMd5},
	md5Datum{"135745", "D89ubl/e", "SdHoMvPduS1kS3KVqEw9W.", PrefixCryptMd5},
	md5Datum{"603762004", "D89ubl/e", "1FQtoOElFQQCBL53IT2LL0", PrefixCryptMd5},
	md5Datum{"29011985", "D89ubl/e", "xO3.z/20nsNEXnaWJdsfB/", PrefixCryptMd5},
}

var apr1TestData = []md5Datum{
	md5Datum{"mickey5", "gxNb79DX", "6wi9QaGNM5TA0kBKiC4710", PrefixCryptApr1},
	md5Datum{"alexandrew", "kv1uUfCO", "iEwrWojf92uZ/9uhTQmMo.", PrefixCryptApr1},
	md5Datum{"hawaiicats78", "UQ6GxE7V", "OrIqWONGuSV9RfS3B2dfO1", PrefixCryptApr1},
	md5Datum{"DIENOW", "OZ.RwYJH", "AwfW2h0gJnu2fQi0GegVe1", PrefixCryptApr1},
	md5Datum{"e8f685", "9r9GyMpL", "3IiaLNos/tbouLJwsW8ey/", PrefixCryptApr1},
	md5Datum{"Rickygirl03", "0tlsxL/0", "cfS6c2JZjwISRTgFvrMWL1", PrefixCryptApr1},
	md5Datum{"123vb123", "/4XFfQuK", "bnMIHM0j/Cf8apmbvPzn/.", PrefixCryptApr1},
	md5Datum{"sheng060576", "NEJJUzVT", "o/CWI9InAMXWAsbl5gx0p1", PrefixCryptApr1},
	md5Datum{"hansisme", "JAOXCriK", "gB/Yox3wTae3NujwKUiFv1", PrefixCryptApr1},
	md5Datum{"h4ck3rs311t3", "KmkPgS2r", "5qIFMPNVAXzlevkzOQwhj.", PrefixCryptApr1},
	md5Datum{"K90JyTGA", "mM7q5ZHN", "03LeGh9D1CujEBwiVRO6B0", PrefixCryptApr1},
	md5Datum{"aspire5101", "tlxr3zoa", "dQJiJmk4pEtRTssYiLwlv0", PrefixCryptApr1},
	md5Datum{"553568", "YI.r2X/w", "H/1DtcmTHSgcdkgz8NS1W0", PrefixCryptApr1},
	md5Datum{"SRI", "StJ5t4wb", "tIVEx.MPZR1SqDm5y9VCs1", PrefixCryptApr1},
	md5Datum{"maxmus", "ad29tH08", "xEHwr706Yz/3FFGqnVB6l/", PrefixCryptApr1},
	md5Datum{"a5xp9707", "aH0sN4io", "y0heNz5hL67/HA7/7mDRS.", PrefixCryptApr1},
	md5Datum{"tomasrim", "SgbYnJV9", "7Z.enu6vZ7b6Zo7/lYce60", PrefixCryptApr1},
	md5Datum{"2a0mag", "lSOzbc7i", "Ae21yFmdTMpSz.aQsjyoE1", PrefixCryptApr1},
	md5Datum{"wmsfht", "yicl6/5x", "p/dCDdQ0q9lLaZbBJsIDP0", PrefixCryptApr1},
	md5Datum{"webmaster2364288", "PLoY5sMf", "KEDmvJskiSNFwiygtWXin1", PrefixCryptApr1},
	md5Datum{"121516m", "3T5gmyrq", "AucgLmXU53aTQJuRKCFo50", PrefixCryptApr1},
	md5Datum{"T69228803", "Aajhupso", "/EPFyux8bd7Iw.tLevaVE.", PrefixCryptApr1},
	md5Datum{"qq820221", "G43B4jFl", "4TUFaOD7Fz5.lZiq5v8P40", PrefixCryptApr1},
	md5Datum{"chenfy", "mDnux.Mf", "vXsdihwaTLCJTHnuk9/cK/", PrefixCryptApr1},
	md5Datum{"www.debure.net", "bZzoRW4K", "DfI3Col55.57HP3FW4L1h.", PrefixCryptApr1},
	md5Datum{"1333e763", "rRvCcrzo", "plG5/rpEPSM7uc3bro6P51", PrefixCryptApr1},
	md5Datum{"burberries", "Qx6JtYcz", "10t2dI6u0LyNBjeCAQ.3z1", PrefixCryptApr1},
	md5Datum{"chanmee14", "p9t9dUC1", "Nlr96oZWIe/VVpYBUgG6q0", PrefixCryptApr1},
	md5Datum{"65432106543210", "CBG7TUqG", "Olyygy0L6HfSPfkLg24U60", PrefixCryptApr1},
	md5Datum{"powernet", "ogVPlakG", ".SLiqbN/KUECQ6pgdck2/.", PrefixCryptApr1},
	md5Datum{"a2d8i6a7", "sNrtmvPF", "rvbRuKdcPPvN.dK.mHeYq/", PrefixCryptApr1},
	md5Datum{"gvs9ptc", "gQgMMxVG", "5sI4ezBQxqpfh14AvEEVU0", PrefixCryptApr1},
	md5Datum{"Pookie", "x.wVLgoG", "HTj5gT.lQ71BpifSlcQVy1", PrefixCryptApr1},
	md5Datum{"lorissss", "O0ySiIf4", "AmmYBbHWjfiVcGEbl4wiy/", PrefixCryptApr1},
	md5Datum{"ess", "nE19zEmy", "Rg3/wMTNMVOkbhez/QhD//", PrefixCryptApr1},
	md5Datum{"sparra", "By1OjZuF", "PRY4G6D8u3aFhruSTgIQC.", PrefixCryptApr1},
	md5Datum{"allysson", "mI6fsU64", "WqCg/f9CpYr4586AVr6nP.", PrefixCryptApr1},
	md5Datum{"99128008", "LQLXA.du", "kazspxn165TFSiDavu75N/", PrefixCryptApr1},
	md5Datum{"evisanne", "AhDCR8bW", "2lR137DLMfr1mQ9xLlMsw0", PrefixCryptApr1},
	md5Datum{"qfxg7x9l", "ZAGBUFGw", "HI3fWMR0Y6Z4U3MSc70sd.", PrefixCryptApr1},
	md5Datum{"03415", "nkFIBpLJ", "AvABMUIgvoMp0zmOTCwCG1", PrefixCryptApr1},
	md5Datum{"87832309", "WbCq7Hv8", "dxe0LoM3vlD.t/A/3Cfd11", PrefixCryptApr1},
	md5Datum{"816283", "PrEjUTNt", "vGLTgLqJp9XEtwEJBv5XF.", PrefixCryptApr1},
	md5Datum{"banach12", "S1G5jLiH", "CySeS1zgVlMLLElxG6Dmw0", PrefixCryptApr1},
	md5Datum{"sjdszpsc", "QmuQrgcB", "xZk5zcK2QRF8PZ24P9vPr1", PrefixCryptApr1},
	md5Datum{"changsing", "Z0i29yA5", "KnTYiWEZQYzQlH/SxQ7Qp/", PrefixCryptApr1},
	md5Datum{"56339388", "RZlCHiTm", "8mFKCLkRHxoJ2ieVa.K79/", PrefixCryptApr1},
	md5Datum{"52114157", "3NkMs.IK", "02HiBvqlIVA.hLbktlHsD1", PrefixCryptApr1},
	md5Datum{"jinebimb", "1ww3avga", "haxtp7TGUm9PHPBrBeM9u.", PrefixCryptApr1},
	md5Datum{"erol43", ".aE1EJya", "3zkhvRyNbF.DOOyJSPSJ21", PrefixCryptApr1},
	md5Datum{"2yagos", "L0YlhvFW", "R0J.Bk9wYb7sQKXBbP4AN/", PrefixCryptApr1},
	md5Datum{"habparty!", "vveX0m/D", "hPoF3j.Ac5zSOAmHBZklT.", PrefixCryptApr1},
	md5Datum{"tangjianhui", "8Ivzj66d", "J4A.NOn6TRk4RYC9oGqIB/", PrefixCryptApr1},
	md5Datum{"serandah", "v9AJex0e", "qn/isKH9e6EG66KCtFdmI1", PrefixCryptApr1},
	md5Datum{"mirrages", "UM0E3yNn", "4V4IJI2Q0Bqh0EG8HAHbq0", PrefixCryptApr1},
	md5Datum{"mantgaxxl", "1spakyg4", "NwPcxatLI7bWUpeDzAw2h1", PrefixCryptApr1},
	md5Datum{"45738901", "oepJpf/s", "p0F.JGVJCyvUHfWnpF.Wy1", PrefixCryptApr1},
	md5Datum{"g523minna", "yWpavB.B", "q4KExAyIKMKWTLq86n0820", PrefixCryptApr1},
	md5Datum{"j202020", "DTRNSWt7", "2At.lEmBM2waU9F2QsDvd.", PrefixCryptApr1},
	md5Datum{"g@mmaecho", "QGA07jk6", "U9Uw/dD666GNV60hX6AKM/", PrefixCryptApr1},
	md5Datum{"042380", "FDnW17iI", "6jkNwkfAi.4LMYkIkNO2v1", PrefixCryptApr1},
	md5Datum{"ASRuin", "GKFI0Se3", "go4Tko/O9UCA2WtSJBjgc.", PrefixCryptApr1},
	md5Datum{"061990", "yJR0EnuF", "CzzsiUo2Q5cRhtlptUf7D1", PrefixCryptApr1},
	md5Datum{"ysoline", "7D0hCvVq", "HLIRmi013HBi2TgATkgJM.", PrefixCryptApr1},
	md5Datum{"liuzhouzhou", "m.MSvKt4", "oFYUki/pESjwOfF5YH9VO0", PrefixCryptApr1},
	md5Datum{"b0000000wind", "qOQrkTXw", "PJXv2X.0Efe4VUPcvyxA61", PrefixCryptApr1},
	md5Datum{"7913456852", "lPKDpKzC", "q9kt0R9.I4rxhlIcNe2gg1", PrefixCryptApr1},
	md5Datum{"9008", "PYsksC92", "3oqtOxrMnQc1n3GfSIAJM.", PrefixCryptApr1},
	md5Datum{"waitlin11", "x5UDLNO2", "yHLWIm/50ORtDhT56f9bi0", PrefixCryptApr1},
	md5Datum{"8fdakar", "E9a2XIvt", "fcsw4gZfbiDXPywMzwhik1", PrefixCryptApr1},
	md5Datum{"eisball", "gHg16GuT", "DGI/O8HzZemhsQ4o2jA560", PrefixCryptApr1},
	md5Datum{"jenna17", "yzwqt8mS", "3QqqiFB9Z6q1fp4z/q1pU.", PrefixCryptApr1},
	md5Datum{"belkadonam", "iGU4vuaZ", "w3xf5rVAIJYz0dgImL8a2.", PrefixCryptApr1},
	md5Datum{"tfyuj9JW", "5cPUmio7", "wttScNV7Fk4Njs9QX1yUi.", PrefixCryptApr1},
	md5Datum{"nihaijidema", "DZW4Gt4h", "EXlVFPbqnXGPp2vLQT5TK0", PrefixCryptApr1},
	md5Datum{"talapia", "61i3ruRm", "cNcNvti2hQ8mXjLahFnSb/", PrefixCryptApr1},
	md5Datum{"7376220", "Z89Ynh0K", "A2k6aLQnMOa2uwXX8MJZf1", PrefixCryptApr1},
	md5Datum{"c7m8e1xsc3", "QRn4AsCM", "gUztH0RWKuX1Vy0WaYfdC1", PrefixCryptApr1},
	md5Datum{"84129793", "rghudgt5", "XA7QLtfRq84JHtbjdke0I.", PrefixCryptApr1},
	md5Datum{"test1000", "zwkIVA3j", "Iuz7zNyLvIiKWIl2VA8bl.", PrefixCryptApr1},
	md5Datum{"ecmanhatten", "zfVlWDS.", "emJhRC3N0SnvZLo5en4zE0", PrefixCryptApr1},
	md5Datum{"EvanYo3327", "VDajAiZs", "lMKGzN91BhIX0hHCNqErU1", PrefixCryptApr1},
	md5Datum{"269john139", "Ryash8LF", "u96Rir1Izuwf/oHnaykmS/", PrefixCryptApr1},
	md5Datum{"3348159zw", "fdErikUY", ".gX/8MNguTOTWT35m4DCy/", PrefixCryptApr1},
	md5Datum{"lu184020", "uabGv1xC", "X5NNdH/1dzD0gQUyHwzKB0", PrefixCryptApr1},
	md5Datum{"aszasw", "41WiK.i.", "2q1CW/s4oRBLAFxmLESmO1", PrefixCryptApr1},
	md5Datum{"33059049", "bYPWMY2a", "fvKkFR1RRccGtIUhLuvBR0", PrefixCryptApr1},
	md5Datum{"li3255265", "FTGQVCcu", "QS/ub5DGLK/wgfkYQ0DBR.", PrefixCryptApr1},
	md5Datum{"kerrihayes", "cFc9bc86", "3cVFy8/qB/fNGNueG65vG0", PrefixCryptApr1},
	md5Datum{"0167681809", "A5TvYYWy", "s4HBh0Wum2QQj1c9e0s79.", PrefixCryptApr1},
	md5Datum{"stefano123", "YNrpseN3", "Yt52Yo9IEBs2LpX7A/CUb0", PrefixCryptApr1},
	md5Datum{"15054652730", "12CL4km4", "NJm8fh.JFi5dE.p6A9g7v/", PrefixCryptApr1},
	md5Datum{"natdvd213", "hssJjJTG", "dDK3pbBFTLbEigu.eCN7s.", PrefixCryptApr1},
	md5Datum{"680929", "iaZlOft5", "w7iC6f5BUzuXox9THmHuj1", PrefixCryptApr1},
	md5Datum{"steelpad8", "mAoHmdUe", "5HePkkuSVu9F2UYgCvn0M.", PrefixCryptApr1},
	md5Datum{"374710", "RFR4xs7H", "9GH0NjiDIgBD0t.w5/fwt0", PrefixCryptApr1},
	md5Datum{"394114", "Jt2syL5H", "tJ18tBNlcBEBqphUQc9jm.", PrefixCryptApr1},
	md5Datum{"24347", "QnSWI03c", "8GC6c0AwpC.c8j4H7/9QU0", PrefixCryptApr1},
	md5Datum{"krait93", "bwzDGet.", "ntnX3fwzi3Zzhy0eHuwA9.", PrefixCryptApr1},
	md5Datum{"5164794", "gkhv.jfD", "2fljug5HHu01vs.6KGJXQ.", PrefixCryptApr1},
	md5Datum{"rswCyJE5", "HzyuhjzZ", "pXmWtTfn0/1voBaBkNaRy0", PrefixCryptApr1},
	md5Datum{"31480019", "ZZc0Ogd8", "1TNy1gTG6GLc.P/98kXXT.", PrefixCryptApr1},
	md5Datum{"19830907ok", "4t6oHDY9", "kFoi2gvPcKMZs.AiGq1yb1", PrefixCryptApr1},
	md5Datum{"zlsmhzlsmh", "cih9diuY", "AwNc6TaKzFm9c8.kQxfwN1", PrefixCryptApr1},
	md5Datum{"Zengatsu", "wuXDXGlS", "FXFvRPPs7HHg96sSCFnFM1", PrefixCryptApr1},
	md5Datum{"0127603331", "z3inhAFw", "vkfbG7KVT4SYHiUn7Yqrz1", PrefixCryptApr1},
	md5Datum{"axelle77", "jydGNcWd", "qz3N5yqg0woVcZ6TN7SHr0", PrefixCryptApr1},
	md5Datum{"password2147", "GoP2TF8P", "c/b36Y.Qg/Grq7b7p.jbl.", PrefixCryptApr1},
	md5Datum{"olixkl8b", "wxkU6WKQ", "IlhCpPwTWvESASvpOToqh.", PrefixCryptApr1},
	md5Datum{"maiwen", "7JgCOFuj", "0WVRunftYuoR3o5ktLMdM1", PrefixCryptApr1},
	md5Datum{"198613", "Vai72CeM", "6WWXwZhxx/EW0IONm7n0A.", PrefixCryptApr1},
	md5Datum{"s17kr8wu", "uNqfw7fr", "NAmeX1Mag2xf5lOCxGrcx/", PrefixCryptApr1},
	md5Datum{"biker02", ".dmc8gVd", "ZB4OmwWIeJ5Iy66Ta/7mU0", PrefixCryptApr1},
	md5Datum{"m1399", "vg1vnQVK", "UUqQibheBizuB0JxR1rbz/", PrefixCryptApr1},
	md5Datum{"a2dc6a", "lsH2FMPS", "dBBuRArwOlN/1p1BuncB3/", PrefixCryptApr1},
	md5Datum{"zhd8902960", "rMGc2ODd", "jG6/9kzAkMHFVAYYVEKN60", PrefixCryptApr1},
	md5Datum{"parasuta", "GeWoySy2", "WZ9pwqAb72tKP0xob81Ho0", PrefixCryptApr1},
	md5Datum{"the1secret", "7LW61iOz", "a9dFA0cRmBIuaxbBqnT/w/", PrefixCryptApr1},
	md5Datum{"teddy14", "GJ9nS.Cn", "jwpBiFBLr1XIo.J5klB39.", PrefixCryptApr1},
	md5Datum{"4516388amt", "NEgOG19t", "CjfmPSbrJqUx6imCL4WPD/", PrefixCryptApr1},
	md5Datum{"245520", "rEzCqOtj", "sSblCTbLq2XDMTeDjYHMu0", PrefixCryptApr1},
	md5Datum{"D34dw00d", "Bugn2T/z", "gTZ/TZ24SMiL1AVQIPgam1", PrefixCryptApr1},
	md5Datum{"officiel", "oCnbHp3p", "lXVZn0P1qWe7dGRkwiJkj0", PrefixCryptApr1},
	md5Datum{"36653665", "cCwY3el7", ".sx/Uv4UADYdLSGjfI0gD0", PrefixCryptApr1},
	md5Datum{"hipol", "b0jFoiEY", "BELMMlTsgKPQ8jSloicdh.", PrefixCryptApr1},
	md5Datum{"Nylon0", "cIw8xXs1", "uiDYDxgJsujwuQtU9Rjyr/", PrefixCryptApr1},
	md5Datum{"caitlyne6", "UffYyvRf", "IHrP6qbFVQEFwcl5BNh9j/", PrefixCryptApr1},
	md5Datum{"dogzilla", "2wvpCP1I", "vudGA0I1SLgEMr6xmmizy.", PrefixCryptApr1},
	md5Datum{"lemegaboss", "QOdrh1Z.", "tFHoBTGKnHwf.MWzX7IBD/", PrefixCryptApr1},
	md5Datum{"c0valerius", "z4ckUwmA", "hq0/DLKdj/0PaR9uJ67fd1", PrefixCryptApr1},
	md5Datum{"liseczek44", "nPnWx0Kv", "FF9VO/i4rbKiD8p.Kor0x0", PrefixCryptApr1},
	md5Datum{"saulosi", "Ox3Y2bAv", "HBZQJd7esDSp/3StMc4xs1", PrefixCryptApr1},
	md5Datum{"53522", "VJn0Rpzz", "7CCQCvpxd3vVsBTIQNHmA1", PrefixCryptApr1},
	md5Datum{"ajgebam", "3wMf8geF", "vyqUHs9babWmAeAIHgcCJ0", PrefixCryptApr1},
	md5Datum{"freshplayer", "H6BJsnhE", "sdUNxVuP0wbG8GXYaaE3H0", PrefixCryptApr1},
	md5Datum{"logistica1", "ycXMTiTE", "8cXiewb9rsL9EuNi.ygaa/", PrefixCryptApr1},
	md5Datum{"12calo66", ".DEY1oqo", "TWeDNa7xX7W3sZWNTZKjG/", PrefixCryptApr1},
	md5Datum{"kenno", "QTq2YDtZ", "3b9BdtbYMbObjKa8.Fvy3/", PrefixCryptApr1},
	md5Datum{"34639399", "qAOAsxTH", "2c8ueVqVPiKAN2ihhA/xw.", PrefixCryptApr1},
	md5Datum{"0408636405", "cLdGrOiq", "WedaFW4qjBLvBKWNZ98ik/", PrefixCryptApr1},
	md5Datum{"weezer12", "mY8WCPXG", "8xEw.ExVVzBOa9u3lJe/W/", PrefixCryptApr1},
	md5Datum{"9888735777", "4l3ZZKUa", "Nor5nWfN0h2HaeQwWBL3u.", PrefixCryptApr1},
	md5Datum{"7771877", "3J0yl1xy", "1h9c1aatf.IaVJvkATLhE0", PrefixCryptApr1},
	md5Datum{"6620852", "UNtXqO0n", "Ag6gmPaH1guubjCy4bJHr0", PrefixCryptApr1},
	md5Datum{"98billiards", "4GJSSWxR", "wNggaBr4TH94zYGEuDvWX1", PrefixCryptApr1},
	md5Datum{"angelik", "Wo9Y7PP9", "btm.n8EiQMUnAFXtlqMpp/", PrefixCryptApr1},
	md5Datum{"86815057", "59qG1lpq", "C1efDS5Cyz33AEdcqNNjP/", PrefixCryptApr1},
	md5Datum{"p16alfalfa", "VW75OiLp", "EeU9NvGQn3l0es.EqOJyt1", PrefixCryptApr1},
	md5Datum{"7236118", "3mis3uOG", "sXNyXtdsWoNUpMaipVw3a.", PrefixCryptApr1},
	md5Datum{"glock17l", "J1Vs.bJ4", "AULv/cwYjMeBoMTvEZXvU.", PrefixCryptApr1},
	md5Datum{"sigmundm", ".k9ZvRfT", "lbGDjiA90kolu9DzQLOvv1", PrefixCryptApr1},
	md5Datum{"ltbgeqsd", "WT1wTKP8", "UDawOWZ73u8wBBZ7ohlSP0", PrefixCryptApr1},
	md5Datum{"wqnd8k2m", "mqiUjAJl", "xYZ0sN8LEwKrxU1g1Did30", PrefixCryptApr1},
	md5Datum{"yangjunjie", "wMWIiKAK", "yScptAfXmU8DVl6AVoAWB0", PrefixCryptApr1},
	md5Datum{"manjinder", "dOljUCkA", "pEb7LT2zG/qezaTTzd1Nj.", PrefixCryptApr1},
	md5Datum{"nick2000", "9qhbsAfO", ".peZB9DgrJqAKlp2R1Nq70", PrefixCryptApr1},
	md5Datum{"193416", "Tke5EI49", "2suXXCRZuzJvjJ7QcJQMU1", PrefixCryptApr1},
	md5Datum{"pang168", "goNotyBA", "/lhn.zMA5z.a2VF31jaO3.", PrefixCryptApr1},
	md5Datum{"454016", "1MdFKwJb", "/MBNPsDN66rZdg1SGQeKj1", PrefixCryptApr1},
	md5Datum{"phair08", "B3uB4Hl/", "LUqRKHuzcnb2q6xwqVok11", PrefixCryptApr1},
	md5Datum{"10252007cw", "ewVqnTQ1", "HkdOCIGKHYg193aUfQuer.", PrefixCryptApr1},
	md5Datum{"zhuzhuzhu", "BiILrcFo", "tqGhsuOrQDvg/JPV00RSd/", PrefixCryptApr1},
	md5Datum{"metafunds", "dLMwXEWa", "Hq/WjMSgbxkp.wCelyfRX.", PrefixCryptApr1},
	md5Datum{"smash", "aMgvovYi", "op3FHJ5OuM2tS93TKnhoc1", PrefixCryptApr1},
	md5Datum{"76387638", "GanQOcQh", "G5qdkoizpSOjWFc3PeL8D.", PrefixCryptApr1},
	md5Datum{"S226811954", "GF9EM5zg", "whu07gAcDNRBfRInKdQz2.", PrefixCryptApr1},
	md5Datum{"mintymoo00", "jDnIOwmz", "vBkkiacYuF8kcp1Nw3tf/1", PrefixCryptApr1},
	md5Datum{"seven711", "mwX.ezPE", "58Q31F7jya8UTnrFUzwO41", PrefixCryptApr1},
	md5Datum{"924414", "wcsVK7PY", "iOErsaSDD8l478QPn/ecp.", PrefixCryptApr1},
	md5Datum{"changchengxu", "ON3zxaJ9", "4K0aR4n6JwbGM8jiE78eo1", PrefixCryptApr1},
	md5Datum{"alaska58", "KIIvW1ib", "ZqJQRoEoDpx30bt4HkZNO0", PrefixCryptApr1},
	md5Datum{"7678208", "xLTFhFu0", "wgkf1zwnwG.rwUGaHlzKK/", PrefixCryptApr1},
	md5Datum{"szazsoo73", "S8RvlMwv", "XKeXw9RfHH163LjG.yQ4/0", PrefixCryptApr1},
	md5Datum{"3830371", "E1WhUznq", "qUOza3gf2ZzUohYpnA/Gt/", PrefixCryptApr1},
	md5Datum{"0qdzx66b", "zSbUMRoi", "EJKnTL40qyiKNTWdOkg8K1", PrefixCryptApr1},
	md5Datum{"09124248099", "vkxQrmli", "gfLBcPOpLI.x4BHcGgG5o1", PrefixCryptApr1},
	md5Datum{"bachrain", "i74JdOeY", "l/rxskCai9U2yu6QAuYiP0", PrefixCryptApr1},
	md5Datum{"sJsSdFBY", "Ucs2cgJv", "ltZWhw3rvDThU3h4wTiMR0", PrefixCryptApr1},
	md5Datum{"676215000", "PJ52qkEa", "FVxkESgiPU8HVk9CVr5Aw0", PrefixCryptApr1},
	md5Datum{"nimamapwoaini", "iJhvvMzV", "c11ZLkLbU3oTL0tO4Uc2b0", PrefixCryptApr1},
	md5Datum{"nitsuj", "Eg6C/017", "PBjnkuRuhfwSMso1of0CU/", PrefixCryptApr1},
	md5Datum{"cukierek2003", "DtaGU5uw", "wj9U6W39HosDe4d20aq9b0", PrefixCryptApr1},
	md5Datum{"seeder", "Hu7E7fh9", "ro5jNBVSUr7P3xXB7bWTs1", PrefixCryptApr1},
	md5Datum{"00167148786", "kIAtp5Qp", "0mGyQcPNotlS9PXmD8VLX/", PrefixCryptApr1},
	md5Datum{"ashok198", "yz/u5zIx", "TcuTnX2cLRkGGPWuQ1DHe0", PrefixCryptApr1},
	md5Datum{"kt2116", "zIlMHa5m", "v.HKzAXRicCxQlNwap5r5/", PrefixCryptApr1},
	md5Datum{"another82", "kf0a2hjv", ".8kEpY7NyyNfBs4Udeu2T.", PrefixCryptApr1},
	md5Datum{"75995794", "2AcSlaOt", "PdPz3ooJyaCM4rD9AuS4c/", PrefixCryptApr1},
	md5Datum{"19901130", "4wioa3Us", "uaKSWrWjJlqHdsqBdF7Zr.", PrefixCryptApr1},
	md5Datum{"gijs010389", "4D9hzr6I", "PsnXK455GeQ3NCdOHmoSY1", PrefixCryptApr1},
	md5Datum{"26263199", "rXOrEHJ9", "atQhaNEYAfdzht02mRZcg.", PrefixCryptApr1},
	md5Datum{"hi1j42x8", "i8PdGfO7", "Xv.aSLFQjyqbJ1KnM9hCs1", PrefixCryptApr1},
	md5Datum{"6922235", "I2xWkhl3", "oth511sBJphjpr0chWodC1", PrefixCryptApr1},
	md5Datum{"67749330", "AGNgrF8B", "KBcUjzo9d3pXFNsUCD6Ur1", PrefixCryptApr1},
	md5Datum{"ccpatrik", "zuNtiCs2", "54MqesBdp3RoL98/fklXb/", PrefixCryptApr1},
	md5Datum{"summer3011", "ZK2FB9JV", "8x8Ug7Jh3oWXgxWrLBuhr.", PrefixCryptApr1},
	md5Datum{"331516", "UoqGMAIH", "bEG70EwRgt0SC6h5nr1wY1", PrefixCryptApr1},
	md5Datum{"135745", "DTVm48a7", "KE/H8KTGE0gi9wxM.ZzOs/", PrefixCryptApr1},
	md5Datum{"603762004", "0B44zHt5", "Xsbx3F0DtToD.KHYc5ViP1", PrefixCryptApr1},
	md5Datum{"29011985", "2YOvrTZM", "/n5Fol4IfYqLv9tS/QWWj0", PrefixCryptApr1},
	md5Datum{"V3RySEcRe7", "D89ubl/e", "x7jjQjtlxgJTcrvl54e3W.", PrefixCryptMd5},
}

func Test_apr1Md5(t *testing.T) {
	for _, v := range apr1TestData {
		if r := md5Crypt(v.password, v.salt, v.prefix); r != v.hashed {
			t.Errorf("apr1Md5(%v,%v) is wrong: %v != %v", v.password, v.salt, r, v.hashed)
		}
	}

	for _, v := range md5CryptTestData {
		if r := md5Crypt(v.password, v.salt, v.prefix); r != v.hashed {
			t.Errorf("apr1Md5(%v,%v) is wrong: %v != %v", v.password, v.salt, r, v.hashed)
		}
	}
}

func Test_Md5(t *testing.T) {
	for _, v := range apr1TestData {
		text := fmt.Sprintf(v.prefix+"%s$%s", v.salt, v.hashed)
		testParserGood(t, "md5", AcceptMd5, RejectMd5, text, v.password)
	}

	for _, v := range md5CryptTestData {
		text := fmt.Sprintf(v.prefix+"%s$%s", v.salt, v.hashed)
		testParserGood(t, "md5", AcceptMd5, RejectMd5, text, v.password)
	}
	testParserBad(t, "md5", AcceptMd5, RejectMd5, "$apr1$nosalt")
	testParserBad(t, "md5", AcceptMd5, RejectMd5, "$1$nosalt")
	testParserNot(t, "md5", AcceptMd5, RejectMd5, "plain")
	testParserNot(t, "md5", AcceptMd5, RejectMd5, "{SHA}plain")
}
